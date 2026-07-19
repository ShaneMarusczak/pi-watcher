//! The probe/persist/notify loop. All monitoring judgement lives in
//! `engine`; this module owns the clocks, sockets, database, and signals.

use crate::config::Config;
use crate::engine::{Engine, Layer, ResumeLayer, ResumeState, ResumeTarget};
use crate::notify::{Msg, Notifier};
use crate::probes::{self, ProbeResult, ProbeSpec};
use crate::store::Store;
use crate::web::Shared;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn local_hms() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Rebuild target/layer state from the database so a restart mid-outage
/// doesn't double-count the outage or lose its duration. Skipped when the
/// last recorded cycle is too old to assume continuity (the world has had
/// time to change while we weren't looking).
fn load_resume(store: &Store, cfg: &Config, now: u64) -> anyhow::Result<Option<ResumeState>> {
    let Some(last) = store.latest_cycle_ts()? else {
        return Ok(None); // fresh database
    };
    if now.saturating_sub(last) > cfg.interval_secs.saturating_mul(10) {
        return Ok(None);
    }

    let mut targets = Vec::with_capacity(cfg.targets.len());
    let mut down_names: Vec<&str> = Vec::new();
    for t in &cfg.targets {
        let rt = match store.target_resume(&t.name)? {
            Some(r) if !r.up => {
                down_names.push(&t.name);
                ResumeTarget {
                    up: false,
                    down_since: r.down_since,
                    notified_down: r.notified,
                }
            }
            _ => ResumeTarget {
                up: true,
                down_since: None,
                notified_down: false,
            },
        };
        targets.push(rt);
    }

    let mut layers = HashMap::new();
    for layer in [Layer::Lan, Layer::Gateway, Layer::Internet, Layer::Dns] {
        if !cfg.targets.iter().any(|t| t.layer == layer) {
            continue;
        }
        if let Some((down_since, notified)) = store.layer_resume(layer.as_str())? {
            layers.insert(
                layer,
                ResumeLayer {
                    down_since,
                    notified_down: notified,
                },
            );
        }
    }

    if down_names.is_empty() && layers.is_empty() {
        return Ok(None); // everything was up: same as a fresh start
    }
    println!(
        "[resume] restored state from database ({} down: {})",
        down_names.len() + layers.len(),
        layers
            .keys()
            .map(|l| l.as_str().to_string())
            .chain(down_names.iter().map(|n| n.to_string()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(Some(ResumeState { targets, layers }))
}

pub async fn run(
    cfg: Config,
    mut store: Store,
    notifier: Notifier,
    shared: Arc<Shared>,
) -> anyhow::Result<()> {
    // Already validated at config load; re-propagating beats a panicking call.
    let specs: Vec<ProbeSpec> = cfg
        .targets
        .iter()
        .map(|t| t.probe_spec())
        .collect::<anyhow::Result<_>>()?;
    let needs_ping = specs.iter().any(|s| matches!(s, ProbeSpec::Ping(_)));
    // Arc, not a bare clone per task: surge-ping's Drop marks the shared reply
    // map destroyed when ANY clone drops, killing pings for every other clone.
    let ping_client = if needs_ping {
        Some(Arc::new(probes::make_ping_client()?))
    } else {
        None
    };
    let timeout = Duration::from_secs(cfg.probe_timeout_secs);
    let ident_base = (std::process::id() & 0x7fff) as u16;

    let resume = match load_resume(&store, &cfg, unix_now()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[resume] could not restore state ({e}) - starting fresh");
            None
        }
    };
    let mut engine = Engine::new(cfg.clone(), unix_now(), resume);

    if cfg.startup_message {
        notifier.send(Msg {
            title: "pi-watcher started".into(),
            body: format!(
                "{} - watching {} targets every {}s. Web UI on {}.",
                local_hms(),
                cfg.targets.len(),
                cfg.interval_secs,
                cfg.web.listen
            ),
            priority: 2,
            tags: "eyes",
        });
    }

    let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Persistent streams: signals arriving while a cycle is being processed
    // are buffered and picked up at the next select, not dropped.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let mut seq: u16 = 0;
    let mut last_prune: Option<Instant> = None;

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = sigint.recv() => {
                println!("[pi-watcher] interrupted, shutting down");
                return Ok(());
            }
            _ = sigterm.recv() => {
                println!("[pi-watcher] SIGTERM, shutting down");
                return Ok(());
            }
        }
        seq = seq.wrapping_add(1);
        let ts = unix_now();

        // Probe everything concurrently.
        let mut handles = Vec::with_capacity(specs.len());
        for (i, spec) in specs.iter().enumerate() {
            let spec = spec.clone();
            let client = ping_client.clone();
            let ident = ident_base.wrapping_add(i as u16);
            handles.push(tokio::spawn(async move {
                probes::run_probe(&spec, client.as_deref(), ident, seq, timeout).await
            }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(
                h.await
                    .unwrap_or_else(|_| ProbeResult::fail("probe task panicked".into())),
            );
        }

        let rows: Vec<(String, bool, Option<f64>)> = cfg
            .targets
            .iter()
            .zip(&results)
            .map(|(t, r)| (t.name.clone(), r.ok, r.latency_ms))
            .collect();
        if let Err(e) = store.insert_cycle(ts, &rows) {
            eprintln!("[db] insert failed: {e}");
        }

        let events = engine.evaluate(ts, Instant::now(), &results);
        for ev in &events {
            println!("[event] {} {}: {}", ev.layer.as_str(), ev.kind, ev.message);
            if let Err(e) = store.insert_event(
                ts,
                ev.layer.as_str(),
                ev.kind,
                ev.target.as_deref(),
                &ev.message,
                ev.duration_secs,
                ev.notify,
            ) {
                eprintln!("[db] event insert failed: {e}");
            }
            if ev.notify {
                notifier.send(Msg {
                    title: ev.title.clone(),
                    body: format!("{} - {}", local_hms(), ev.message),
                    priority: ev.priority,
                    tags: ev.tags,
                });
            }
        }

        // Publish the snapshot for the web UI.
        *shared.snapshot.write().await = Some(engine.snapshot(ts));

        if last_prune.is_none_or(|t| t.elapsed() >= Duration::from_secs(86400)) {
            let cutoff = ts.saturating_sub(cfg.retention_days * 86400);
            match store.prune_samples(cutoff) {
                Ok(n) if n > 0 => println!(
                    "[db] pruned {n} samples older than {} days",
                    cfg.retention_days
                ),
                Ok(_) => {}
                Err(e) => eprintln!("[db] prune failed: {e}"),
            }
            last_prune = Some(Instant::now());
        }
    }
}
