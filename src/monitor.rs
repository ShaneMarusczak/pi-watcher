use crate::config::Config;
use crate::notify::{Msg, Notifier};
use crate::probes::{self, ProbeResult, ProbeSpec};
use crate::store::Store;
use crate::web::Shared;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The probe ladder, plus a free-form "host" layer for any other machines
/// worth watching. When a layer this one depends on is down, its alerts are
/// suppressed (recorded in the DB, but not notified), because they're implied.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Lan,
    Gateway,
    Internet,
    Dns,
    /// User-chosen extra hosts: charted and alerted per target, never part of
    /// the internet verdict or the ladder.
    Host,
}

impl Layer {
    pub const ALL: [Layer; 5] = [
        Layer::Lan,
        Layer::Gateway,
        Layer::Internet,
        Layer::Dns,
        Layer::Host,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Lan => "lan",
            Layer::Gateway => "gateway",
            Layer::Internet => "internet",
            Layer::Dns => "dns",
            Layer::Host => "host",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Layer::Lan => "LAN",
            Layer::Gateway => "WAN gateway",
            Layer::Internet => "Internet",
            Layer::Dns => "DNS",
            Layer::Host => "Watched hosts",
        }
    }

    /// Layers whose outage makes this one's failure unremarkable. A watched
    /// host only depends on the LAN: the internet being down says nothing
    /// about a NAS in the closet.
    fn implied_by(self) -> &'static [Layer] {
        match self {
            Layer::Lan => &[],
            Layer::Gateway => &[Layer::Lan],
            Layer::Internet => &[Layer::Lan, Layer::Gateway],
            Layer::Dns => &[Layer::Lan, Layer::Gateway, Layer::Internet],
            Layer::Host => &[Layer::Lan],
        }
    }
}

fn implied_down(layer: Layer, cur: &HashMap<Layer, Status>) -> bool {
    layer
        .implied_by()
        .iter()
        .any(|l| cur.get(l) == Some(&Status::Down))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Up,
    Degraded,
    Down,
}

#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub updated: u64,
    pub interval_secs: u64,
    pub verdict: String,
    pub verdict_status: Status,
    pub layers: Vec<LayerSnap>,
}

#[derive(Clone, Serialize)]
pub struct LayerSnap {
    pub layer: Layer,
    pub label: &'static str,
    pub status: Status,
    pub since: u64,
    pub loss_pct: Option<f64>,
    pub latency_ms: Option<f64>,
    pub targets: Vec<TargetSnap>,
}

#[derive(Clone, Serialize)]
pub struct TargetSnap {
    pub name: String,
    pub up: bool,
    pub last_ms: Option<f64>,
    pub loss_pct: Option<f64>,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn local_hms() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Rolling window per target: None = failed probe, Some(ms) = success.
struct TargetState {
    window: VecDeque<Option<f64>>,
    consec_fail: u32,
    consec_ok: u32,
    up: bool,
    // Per-target alerting state, used for host-layer targets (ladder layers
    // alert at layer granularity instead).
    down_since: Option<u64>,
    notified_down: bool,
}

impl TargetState {
    fn new() -> Self {
        Self {
            window: VecDeque::new(),
            consec_fail: 0,
            consec_ok: 0,
            // Assume healthy at boot so a clean start doesn't fire recovery alerts.
            up: true,
            down_since: None,
            notified_down: false,
        }
    }

    fn record(&mut self, res: &ProbeResult, cap: usize) {
        if self.window.len() >= cap {
            self.window.pop_front();
        }
        self.window.push_back(res.latency_ms);
        if res.ok {
            self.consec_ok += 1;
            self.consec_fail = 0;
        } else {
            self.consec_fail += 1;
            self.consec_ok = 0;
        }
    }

    /// The failure window from an outage would otherwise read as heavy packet
    /// loss and immediately re-alert as "degraded" right after recovery.
    fn reset_window_keep_last(&mut self) {
        let last = self.window.back().copied().flatten();
        self.window.clear();
        if let Some(ms) = last {
            self.window.push_back(Some(ms));
        }
    }

    fn loss_pct(&self) -> Option<f64> {
        if self.window.len() < 3 {
            return None;
        }
        let fails = self.window.iter().filter(|s| s.is_none()).count();
        Some(fails as f64 / self.window.len() as f64 * 100.0)
    }

    fn median_ms(&self) -> Option<f64> {
        let mut ok: Vec<f64> = self.window.iter().filter_map(|s| *s).collect();
        if ok.is_empty() {
            return None;
        }
        ok.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Some(ok[ok.len() / 2])
    }

    fn last_ms(&self) -> Option<f64> {
        self.window.back().copied().flatten()
    }
}

struct LayerState {
    status: Status,
    since: u64,
    notified_down: bool,
    notified_degraded: bool,
    last_degraded_alert: Option<Instant>,
}

#[derive(Clone, Copy)]
struct LayerAgg {
    loss_pct: Option<f64>,
    latency_ms: Option<f64>,
}

struct PendingEvent {
    layer: Layer,
    kind: &'static str,
    title: String,
    message: String,
    duration_secs: Option<u64>,
    notify: bool,
    priority: u8,
    tags: &'static str,
}

pub async fn run(
    cfg: Config,
    mut store: Store,
    notifier: Notifier,
    shared: Arc<Shared>,
) -> anyhow::Result<()> {
    let specs: Vec<ProbeSpec> = cfg
        .targets
        .iter()
        .map(|t| t.probe_spec().expect("validated at load"))
        .collect();
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

    let mut tstates: Vec<TargetState> = cfg.targets.iter().map(|_| TargetState::new()).collect();
    let mut layers: HashMap<Layer, LayerState> = Layer::ALL
        .into_iter()
        .filter(|l| cfg.targets.iter().any(|t| t.layer == *l))
        .map(|l| {
            (
                l,
                LayerState {
                    status: Status::Up,
                    since: unix_now(),
                    notified_down: false,
                    notified_degraded: false,
                    last_degraded_alert: None,
                },
            )
        })
        .collect();

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
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let mut seq: u16 = 0;
    let mut last_prune: Option<Instant> = None;

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = tokio::signal::ctrl_c() => {
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

        // Per-target hysteresis. `went_down` / `came_up` record this cycle's
        // flips for the host-layer event pass below.
        let mut went_down: Vec<usize> = Vec::new();
        let mut came_up: Vec<usize> = Vec::new();
        for (i, res) in results.iter().enumerate() {
            let st = &mut tstates[i];
            st.record(res, cfg.window_samples);
            if st.up && st.consec_fail >= cfg.fail_threshold {
                st.up = false;
                st.down_since = Some(ts);
                went_down.push(i);
                println!(
                    "[target] {} down ({})",
                    cfg.targets[i].name,
                    res.error.as_deref().unwrap_or("?")
                );
            } else if !st.up && st.consec_ok >= cfg.recover_threshold {
                st.up = true;
                st.reset_window_keep_last();
                came_up.push(i);
                println!("[target] {} back up", cfg.targets[i].name);
            }
        }

        // Layer evaluation in rank order, so attribution and suppression can
        // read the already-updated status of lower layers.
        let mut cur: HashMap<Layer, Status> = layers.iter().map(|(l, s)| (*l, s.status)).collect();
        let mut aggs: HashMap<Layer, LayerAgg> = HashMap::new();
        let mut events: Vec<PendingEvent> = Vec::new();

        for layer in Layer::ALL {
            let idxs: Vec<usize> = cfg
                .targets
                .iter()
                .enumerate()
                .filter(|(_, t)| t.layer == layer)
                .map(|(i, _)| i)
                .collect();
            if idxs.is_empty() {
                continue;
            }

            // Host targets are independent machines: no layer-level state
            // machine or aggregates. The card goes red if any of them is down;
            // per-target events are handled in their own pass below.
            if layer == Layer::Host {
                let any_down = idxs.iter().any(|&i| !tstates[i].up);
                let new_status = if any_down { Status::Down } else { Status::Up };
                let ls = layers.get_mut(&layer).expect("layer state exists");
                if new_status != ls.status {
                    ls.status = new_status;
                    ls.since = ts;
                }
                cur.insert(layer, new_status);
                aggs.insert(
                    layer,
                    LayerAgg {
                        loss_pct: None,
                        latency_ms: None,
                    },
                );
                continue;
            }

            let any_up = idxs.iter().any(|&i| tstates[i].up);
            // min across targets: only problems on the shared path (the
            // uplink) affect every anchor at once.
            let loss = idxs
                .iter()
                .filter_map(|&i| tstates[i].loss_pct())
                .fold(None, |acc: Option<f64>, v| {
                    Some(acc.map_or(v, |a| a.min(v)))
                });
            let lat = idxs
                .iter()
                .filter_map(|&i| tstates[i].median_ms())
                .fold(None, |acc: Option<f64>, v| {
                    Some(acc.map_or(v, |a| a.min(v)))
                });
            aggs.insert(
                layer,
                LayerAgg {
                    loss_pct: loss,
                    latency_ms: lat,
                },
            );

            let base = if any_up { Status::Up } else { Status::Down };
            let mut new_status = base;
            if layer == Layer::Internet && base == Status::Up && cfg.degraded.enabled {
                let lossy = loss.is_some_and(|l| l >= cfg.degraded.loss_pct);
                let slow = lat.is_some_and(|m| m >= cfg.degraded.latency_ms);
                if lossy || slow {
                    new_status = Status::Degraded;
                }
            }

            let ls = layers.get_mut(&layer).expect("layer state exists");
            let prev = ls.status;
            if new_status != prev {
                let lower_down = implied_down(layer, &cur);
                match (prev, new_status) {
                    (_, Status::Down) => {
                        let notify = !lower_down;
                        ls.notified_down = notify;
                        events.push(PendingEvent {
                            layer,
                            kind: "down",
                            title: down_title(layer),
                            message: down_message(layer, &cur),
                            duration_secs: None,
                            notify,
                            priority: 4,
                            tags: "rotating_light",
                        });
                    }
                    (Status::Down, _) => {
                        let dur = ts.saturating_sub(ls.since);
                        events.push(PendingEvent {
                            layer,
                            kind: "up",
                            title: format!("{} recovered", layer.label()),
                            message: format!("Back up after {}.", fmt_duration(dur)),
                            duration_secs: Some(dur),
                            notify: ls.notified_down && !lower_down,
                            priority: 3,
                            tags: "white_check_mark",
                        });
                        ls.notified_down = false;
                    }
                    (Status::Up, Status::Degraded) => {
                        let cooled = ls.last_degraded_alert.is_none_or(|t| {
                            t.elapsed() >= Duration::from_secs(cfg.degraded.cooldown_mins * 60)
                        });
                        let notify = cooled && !lower_down;
                        if notify {
                            ls.last_degraded_alert = Some(Instant::now());
                        }
                        ls.notified_degraded = notify;
                        events.push(PendingEvent {
                            layer,
                            kind: "degraded",
                            title: "Internet degraded".into(),
                            message: format!(
                                "{:.0}% loss, median {} over the last {} - thresholds are {:.0}% / {:.0} ms.",
                                loss.unwrap_or(0.0),
                                lat.map_or("n/a".to_string(), |m| format!("{m:.0} ms")),
                                fmt_duration(cfg.window_samples as u64 * cfg.interval_secs),
                                cfg.degraded.loss_pct,
                                cfg.degraded.latency_ms
                            ),
                            duration_secs: None,
                            notify,
                            priority: 3,
                            tags: "warning",
                        });
                    }
                    (Status::Degraded, Status::Up) => {
                        let dur = ts.saturating_sub(ls.since);
                        events.push(PendingEvent {
                            layer,
                            kind: "degraded_end",
                            title: "Internet back to normal".into(),
                            message: format!("Degraded for {}.", fmt_duration(dur)),
                            duration_secs: Some(dur),
                            notify: ls.notified_degraded,
                            priority: 2,
                            tags: "white_check_mark",
                        });
                        ls.notified_degraded = false;
                    }
                    _ => {}
                }
                ls.status = new_status;
                ls.since = ts;
                cur.insert(layer, new_status);
            }
        }

        // A layer that went down while a lower layer was already down never
        // alerted (suppressed as implied). If the lower layer has recovered
        // but this one is still down, that outage now stands on its own -
        // send the overdue alert. Uses kind "still_down" so outage counts
        // (which tally "down" events) aren't inflated.
        for layer in Layer::ALL {
            if layer == Layer::Host {
                continue; // host targets get per-target treatment below
            }
            let Some(ls) = layers.get_mut(&layer) else {
                continue;
            };
            if ls.status != Status::Down || ls.notified_down || implied_down(layer, &cur) {
                continue;
            }
            ls.notified_down = true;
            events.push(PendingEvent {
                layer,
                kind: "still_down",
                title: down_title(layer),
                message: format!(
                    "{} Still down after {}.",
                    down_message(layer, &cur),
                    fmt_duration(ts.saturating_sub(ls.since))
                ),
                duration_secs: None,
                notify: true,
                priority: 4,
                tags: "rotating_light",
            });
        }

        // Host-layer targets alert individually: each host is its own story.
        // Same suppression and catch-up rules as layers, per target.
        let host_implied = implied_down(Layer::Host, &cur);
        for (i, t) in cfg.targets.iter().enumerate() {
            if t.layer != Layer::Host {
                continue;
            }
            let st = &mut tstates[i];
            if !st.up {
                if went_down.contains(&i) {
                    let notify = t.alert && !host_implied;
                    st.notified_down = notify;
                    events.push(PendingEvent {
                        layer: Layer::Host,
                        kind: "down",
                        title: format!("{} DOWN", t.name),
                        message: format!("{} ({}) stopped responding.", t.name, t.addr),
                        duration_secs: None,
                        notify,
                        priority: 4,
                        tags: "rotating_light",
                    });
                } else if t.alert && !st.notified_down && !host_implied {
                    st.notified_down = true;
                    events.push(PendingEvent {
                        layer: Layer::Host,
                        kind: "still_down",
                        title: format!("{} DOWN", t.name),
                        message: format!(
                            "{} ({}) is not responding. Still down after {}.",
                            t.name,
                            t.addr,
                            fmt_duration(ts.saturating_sub(st.down_since.unwrap_or(ts)))
                        ),
                        duration_secs: None,
                        notify: true,
                        priority: 4,
                        tags: "rotating_light",
                    });
                }
            } else if came_up.contains(&i) {
                let dur = ts.saturating_sub(st.down_since.unwrap_or(ts));
                events.push(PendingEvent {
                    layer: Layer::Host,
                    kind: "up",
                    title: format!("{} recovered", t.name),
                    message: format!("{} back after {}.", t.name, fmt_duration(dur)),
                    duration_secs: Some(dur),
                    notify: st.notified_down,
                    priority: 3,
                    tags: "white_check_mark",
                });
                st.notified_down = false;
                st.down_since = None;
            }
        }

        for ev in &events {
            println!("[event] {} {}: {}", ev.layer.as_str(), ev.kind, ev.message);
            if let Err(e) = store.insert_event(
                ts,
                ev.layer.as_str(),
                ev.kind,
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
        let layer_snaps: Vec<LayerSnap> = Layer::ALL
            .into_iter()
            .filter_map(|layer| {
                let ls = layers.get(&layer)?;
                let agg = aggs.get(&layer)?;
                let targets = cfg
                    .targets
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| t.layer == layer)
                    .map(|(i, t)| TargetSnap {
                        name: t.name.clone(),
                        up: tstates[i].up,
                        last_ms: tstates[i].last_ms(),
                        loss_pct: tstates[i].loss_pct(),
                    })
                    .collect();
                Some(LayerSnap {
                    layer,
                    label: layer.label(),
                    status: ls.status,
                    since: ls.since,
                    loss_pct: agg.loss_pct,
                    latency_ms: agg.latency_ms,
                    targets,
                })
            })
            .collect();
        let (verdict, verdict_status) = make_verdict(&cur, &aggs);
        *shared.snapshot.write().await = Some(Snapshot {
            updated: ts,
            interval_secs: cfg.interval_secs,
            verdict,
            verdict_status,
            layers: layer_snaps,
        });

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

fn down_title(layer: Layer) -> String {
    match layer {
        Layer::Lan => "LAN DOWN".into(),
        Layer::Gateway => "WAN gateway DOWN".into(),
        Layer::Internet => "Internet DOWN".into(),
        Layer::Dns => "DNS DOWN".into(),
        // Host events carry their own per-target titles; this is a fallback.
        Layer::Host => "Watched host DOWN".into(),
    }
}

fn down_message(layer: Layer, cur: &HashMap<Layer, Status>) -> String {
    match layer {
        Layer::Lan => {
            "The Pi can't reach the LAN router - local network problem (or the Pi itself)."
                .into()
        }
        Layer::Gateway => "The WAN gateway stopped answering pings from the LAN.".into(),
        Layer::Internet => match cur.get(&Layer::Gateway) {
            Some(Status::Down) => {
                "Internet is unreachable and the WAN gateway isn't answering either - \
                 the gateway may be offline or rebooting."
                    .into()
            }
            Some(_) => "Internet is unreachable but the WAN gateway still responds - \
                 the uplink is down."
                .into(),
            None => "Internet is unreachable through the uplink.".into(),
        },
        Layer::Dns => match cur.get(&Layer::Internet) {
            Some(Status::Down) => "DNS lookups failing (internet is down).".into(),
            _ => {
                "DNS lookups are failing while the internet looks fine - check your DNS server."
                    .into()
            }
        },
        Layer::Host => "A watched host stopped responding.".into(),
    }
}

fn make_verdict(cur: &HashMap<Layer, Status>, aggs: &HashMap<Layer, LayerAgg>) -> (String, Status) {
    let Some(&inet) = cur.get(&Layer::Internet) else {
        return (
            "Monitoring (no internet-layer targets configured)".into(),
            Status::Up,
        );
    };
    let inet_agg = aggs.get(&Layer::Internet);
    let detail = || {
        let lat = inet_agg
            .and_then(|a| a.latency_ms)
            .map_or("n/a".to_string(), |m| format!("{m:.0} ms"));
        let loss = inet_agg
            .and_then(|a| a.loss_pct)
            .map_or("n/a".to_string(), |l| format!("{l:.0}%"));
        format!("{lat} median, {loss} loss")
    };
    match inet {
        Status::Up => (format!("Internet OK - {}", detail()), Status::Up),
        Status::Degraded => (
            format!("Internet DEGRADED - {}", detail()),
            Status::Degraded,
        ),
        Status::Down => {
            if cur.get(&Layer::Lan) == Some(&Status::Down) {
                (
                    "Pi is cut off from the LAN - can't judge the uplink".into(),
                    Status::Down,
                )
            } else if cur.get(&Layer::Gateway) == Some(&Status::Down) {
                ("OUTAGE - WAN gateway unreachable".into(), Status::Down)
            } else {
                (
                    "UPLINK OUTAGE - gateway reachable, uplink down".into(),
                    Status::Down,
                )
            }
        }
    }
}
