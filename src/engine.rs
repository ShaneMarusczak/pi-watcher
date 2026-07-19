//! The per-cycle evaluation engine: all monitoring state and alert logic,
//! free of network and storage I/O (it logs target flips, nothing more).
//! `monitor::run` feeds it probe results once per cycle; it returns the
//! events to record and notify. Keeping it self-contained makes the
//! suppression / catch-up / hysteresis rules testable without a network
//! or a database.

use crate::config::Config;
use crate::probes::ProbeResult;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

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

    /// The dependency ladder in rank order - every layer with layer-level
    /// alerting. `Host` is deliberately absent: its targets alert per host.
    pub const LADDER: [Layer; 4] = [Layer::Lan, Layer::Gateway, Layer::Internet, Layer::Dns];

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

/// Rolling window per target: None = failed probe, Some(ms) = success.
struct TargetState {
    window: VecDeque<Option<f64>>,
    consec_fail: u32,
    consec_ok: u32,
    up: bool,
    // Per-target alerting state, used for host-layer targets (ladder layers
    // alert at layer granularity instead).
    down_since: Option<u64>,
    // Set when the down transition was observed by this process; None when the
    // state was rehydrated from the database after a restart. Durations use
    // the monotonic clock when available so an NTP step can't distort them.
    down_since_mono: Option<Instant>,
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
            down_since_mono: None,
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
        ok.sort_by(f64::total_cmp);
        Some(ok[ok.len() / 2])
    }

    fn last_ms(&self) -> Option<f64> {
        self.window.back().copied().flatten()
    }

    fn down_dur_secs(&self, ts: u64, mono: Instant) -> u64 {
        match self.down_since_mono {
            Some(m) => mono.duration_since(m).as_secs(),
            None => ts.saturating_sub(self.down_since.unwrap_or(ts)),
        }
    }
}

struct LayerState {
    status: Status,
    since: u64,
    // See TargetState::down_since_mono.
    since_mono: Option<Instant>,
    notified_down: bool,
    notified_degraded: bool,
    last_degraded_alert: Option<Instant>,
}

impl LayerState {
    fn dur_secs(&self, ts: u64, mono: Instant) -> u64 {
        match self.since_mono {
            Some(m) => mono.duration_since(m).as_secs(),
            None => ts.saturating_sub(self.since),
        }
    }
}

#[derive(Clone, Copy)]
struct LayerAgg {
    loss_pct: Option<f64>,
    latency_ms: Option<f64>,
}

pub struct PendingEvent {
    pub layer: Layer,
    pub kind: &'static str,
    /// Host-layer events carry the target name so state can be rehydrated
    /// per host after a restart; ladder events are layer-wide (None).
    pub target: Option<String>,
    pub title: String,
    pub message: String,
    pub duration_secs: Option<u64>,
    pub notify: bool,
    pub priority: u8,
    pub tags: &'static str,
}

/// State recovered from the database at startup, so a restart in the middle
/// of an outage doesn't reset the story (double-counted outages, lost
/// durations, spurious recovery alerts).
pub struct ResumeState {
    /// Indexed like `cfg.targets`.
    pub targets: Vec<ResumeTarget>,
    pub layers: HashMap<Layer, ResumeLayer>,
}

pub struct ResumeTarget {
    pub up: bool,
    pub down_since: Option<u64>,
    pub notified_down: bool,
}

pub struct ResumeLayer {
    pub down_since: u64,
    pub notified_down: bool,
}

pub struct Engine {
    cfg: Config,
    tstates: Vec<TargetState>,
    layers: HashMap<Layer, LayerState>,
    cur: HashMap<Layer, Status>,
    aggs: HashMap<Layer, LayerAgg>,
}

impl Engine {
    pub fn new(cfg: Config, now: u64, resume: Option<ResumeState>) -> Self {
        let mut tstates: Vec<TargetState> =
            cfg.targets.iter().map(|_| TargetState::new()).collect();
        let mut layers: HashMap<Layer, LayerState> = Layer::ALL
            .into_iter()
            .filter(|l| cfg.targets.iter().any(|t| t.layer == *l))
            .map(|l| {
                (
                    l,
                    LayerState {
                        status: Status::Up,
                        since: now,
                        since_mono: None,
                        notified_down: false,
                        notified_degraded: false,
                        last_degraded_alert: None,
                    },
                )
            })
            .collect();

        if let Some(resume) = resume {
            for (st, rt) in tstates.iter_mut().zip(&resume.targets) {
                if !rt.up {
                    st.up = false;
                    st.down_since = rt.down_since;
                    st.notified_down = rt.notified_down;
                }
            }
            for (layer, rl) in &resume.layers {
                if let Some(ls) = layers.get_mut(layer) {
                    ls.status = Status::Down;
                    ls.since = rl.down_since;
                    ls.notified_down = rl.notified_down;
                }
            }
        }

        let cur = layers.iter().map(|(l, s)| (*l, s.status)).collect();
        Engine {
            cfg,
            tstates,
            layers,
            cur,
            aggs: HashMap::new(),
        }
    }

    /// Feed one cycle of probe results (indexed like `cfg.targets`).
    /// `ts` is the wall-clock cycle timestamp (for records and display);
    /// `mono` is the monotonic now (for durations and cooldowns).
    pub fn evaluate(
        &mut self,
        ts: u64,
        mono: Instant,
        results: &[ProbeResult],
    ) -> Vec<PendingEvent> {
        let cfg = &self.cfg;
        let mut events: Vec<PendingEvent> = Vec::new();

        // Per-target hysteresis. `went_down` / `came_up` record this cycle's
        // flips for the host-layer event pass below.
        let mut went_down: Vec<usize> = Vec::new();
        let mut came_up: Vec<usize> = Vec::new();
        for (i, res) in results.iter().enumerate() {
            let st = &mut self.tstates[i];
            st.record(res, cfg.window_samples);
            if st.up && st.consec_fail >= cfg.fail_threshold {
                st.up = false;
                st.down_since = Some(ts);
                st.down_since_mono = Some(mono);
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
        let mut cur: HashMap<Layer, Status> =
            self.layers.iter().map(|(l, s)| (*l, s.status)).collect();
        let mut aggs: HashMap<Layer, LayerAgg> = HashMap::new();

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
                let any_down = idxs.iter().any(|&i| !self.tstates[i].up);
                let new_status = if any_down { Status::Down } else { Status::Up };
                // Always present: `layers` and `idxs` are built from the same
                // target list.
                let Some(ls) = self.layers.get_mut(&layer) else {
                    continue;
                };
                if new_status != ls.status {
                    ls.status = new_status;
                    ls.since = ts;
                    ls.since_mono = Some(mono);
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

            let any_up = idxs.iter().any(|&i| self.tstates[i].up);
            // min across targets: only problems on the shared path (the
            // uplink) affect every anchor at once.
            let loss = idxs
                .iter()
                .filter_map(|&i| self.tstates[i].loss_pct())
                .fold(None, |acc: Option<f64>, v| {
                    Some(acc.map_or(v, |a| a.min(v)))
                });
            let lat = idxs
                .iter()
                .filter_map(|&i| self.tstates[i].median_ms())
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

            let Some(ls) = self.layers.get_mut(&layer) else {
                continue;
            };
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
                            target: None,
                            title: down_title(layer),
                            message: down_message(layer, &cur),
                            duration_secs: None,
                            notify,
                            priority: 4,
                            tags: "rotating_light",
                        });
                    }
                    (Status::Down, _) => {
                        let dur = ls.dur_secs(ts, mono);
                        events.push(PendingEvent {
                            layer,
                            kind: "up",
                            target: None,
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
                            mono.duration_since(t)
                                >= Duration::from_secs(cfg.degraded.cooldown_mins * 60)
                        });
                        let notify = cooled && !lower_down;
                        if notify {
                            ls.last_degraded_alert = Some(mono);
                        }
                        ls.notified_degraded = notify;
                        events.push(PendingEvent {
                            layer,
                            kind: "degraded",
                            target: None,
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
                        let dur = ls.dur_secs(ts, mono);
                        events.push(PendingEvent {
                            layer,
                            kind: "degraded_end",
                            target: None,
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
                ls.since_mono = Some(mono);
                cur.insert(layer, new_status);
            }
        }

        // A layer that went down while a lower layer was already down never
        // alerted (suppressed as implied). If the lower layer has recovered
        // but this one is still down, that outage now stands on its own -
        // send the overdue alert. Uses kind "still_down" so outage counts
        // (which tally "down" events) aren't inflated. Host targets get
        // per-target treatment below, so this walks the ladder only.
        for layer in Layer::LADDER {
            let Some(ls) = self.layers.get_mut(&layer) else {
                continue;
            };
            if ls.status != Status::Down || ls.notified_down || implied_down(layer, &cur) {
                continue;
            }
            ls.notified_down = true;
            events.push(PendingEvent {
                layer,
                kind: "still_down",
                target: None,
                title: down_title(layer),
                message: format!(
                    "{} Still down after {}.",
                    down_message(layer, &cur),
                    fmt_duration(ls.dur_secs(ts, mono))
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
            let st = &mut self.tstates[i];
            if !st.up {
                if went_down.contains(&i) {
                    let notify = t.alert && !host_implied;
                    st.notified_down = notify;
                    events.push(PendingEvent {
                        layer: Layer::Host,
                        kind: "down",
                        target: Some(t.name.clone()),
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
                        target: Some(t.name.clone()),
                        title: format!("{} DOWN", t.name),
                        message: format!(
                            "{} ({}) is not responding. Still down after {}.",
                            t.name,
                            t.addr,
                            fmt_duration(st.down_dur_secs(ts, mono))
                        ),
                        duration_secs: None,
                        notify: true,
                        priority: 4,
                        tags: "rotating_light",
                    });
                }
            } else if came_up.contains(&i) {
                let dur = st.down_dur_secs(ts, mono);
                events.push(PendingEvent {
                    layer: Layer::Host,
                    kind: "up",
                    target: Some(t.name.clone()),
                    title: format!("{} recovered", t.name),
                    message: format!("{} back after {}.", t.name, fmt_duration(dur)),
                    duration_secs: Some(dur),
                    notify: st.notified_down,
                    priority: 3,
                    tags: "white_check_mark",
                });
                st.notified_down = false;
                st.down_since = None;
                st.down_since_mono = None;
            }
        }

        self.cur = cur;
        self.aggs = aggs;
        events
    }

    /// The current state as the web UI sees it. Call after `evaluate`.
    pub fn snapshot(&self, ts: u64) -> Snapshot {
        let layer_snaps: Vec<LayerSnap> = Layer::ALL
            .into_iter()
            .filter_map(|layer| {
                let ls = self.layers.get(&layer)?;
                let agg = self.aggs.get(&layer)?;
                let targets = self
                    .cfg
                    .targets
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| t.layer == layer)
                    .map(|(i, t)| TargetSnap {
                        name: t.name.clone(),
                        up: self.tstates[i].up,
                        last_ms: self.tstates[i].last_ms(),
                        loss_pct: self.tstates[i].loss_pct(),
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
        let (verdict, verdict_status) = make_verdict(&self.cur, &self.aggs);
        Snapshot {
            updated: ts,
            interval_secs: self.cfg.interval_secs,
            verdict,
            verdict_status,
            layers: layer_snaps,
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
            "The Pi can't reach the LAN router - local network problem (or the Pi itself).".into()
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
            _ => "DNS lookups are failing while the internet looks fine - check your DNS server."
                .into(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;

    const BASE_TS: u64 = 1_700_000_000;
    const INTERVAL: u64 = 30;

    const LAN: &str = r#"
[[targets]]
name = "router"
layer = "lan"
kind = "ping"
addr = "192.168.1.1"
"#;
    const INET: &str = r#"
[[targets]]
name = "cloudflare"
layer = "internet"
kind = "ping"
addr = "1.1.1.1"
"#;
    const NAS: &str = r#"
[[targets]]
name = "nas"
layer = "host"
kind = "ping"
addr = "192.168.1.40"
"#;

    fn cfg(toml: &str) -> Config {
        Config::parse(toml).unwrap()
    }

    fn ok(ms: f64) -> ProbeResult {
        ProbeResult {
            ok: true,
            latency_ms: Some(ms),
            error: None,
        }
    }

    fn fail() -> ProbeResult {
        ProbeResult::fail("test failure".into())
    }

    /// Drives an Engine cycle by cycle with wall and monotonic clocks that
    /// advance in lockstep.
    struct Sim {
        engine: Engine,
        ts: u64,
        mono: Instant,
    }

    impl Sim {
        fn new(config: Config) -> Self {
            Self::resumed(config, None)
        }

        fn resumed(config: Config, resume: Option<ResumeState>) -> Self {
            Sim {
                engine: Engine::new(config, BASE_TS, resume),
                ts: BASE_TS,
                mono: Instant::now(),
            }
        }

        fn cycle(&mut self, results: Vec<ProbeResult>) -> Vec<PendingEvent> {
            self.ts += INTERVAL;
            self.mono += Duration::from_secs(INTERVAL);
            self.engine.evaluate(self.ts, self.mono, &results)
        }
    }

    fn kinds(events: &[PendingEvent]) -> Vec<(&'static str, &'static str, bool)> {
        events
            .iter()
            .map(|e| (e.layer.as_str(), e.kind, e.notify))
            .collect()
    }

    #[test]
    fn down_after_threshold_up_after_recovery_with_duration() {
        let mut sim = Sim::new(cfg(LAN));
        assert!(sim.cycle(vec![fail()]).is_empty());
        assert!(sim.cycle(vec![fail()]).is_empty());
        let evs = sim.cycle(vec![fail()]);
        assert_eq!(kinds(&evs), vec![("lan", "down", true)]);

        assert!(sim.cycle(vec![ok(5.0)]).is_empty());
        assert!(sim.cycle(vec![ok(5.0)]).is_empty());
        let evs = sim.cycle(vec![ok(5.0)]);
        assert_eq!(kinds(&evs), vec![("lan", "up", true)]);
        // Down at cycle 3, up at cycle 6: 3 intervals.
        assert_eq!(evs[0].duration_secs, Some(3 * INTERVAL));
    }

    #[test]
    fn higher_layer_suppressed_then_catches_up_when_lower_recovers() {
        let mut sim = Sim::new(cfg(&format!("{LAN}{INET}")));
        sim.cycle(vec![fail(), fail()]);
        sim.cycle(vec![fail(), fail()]);
        let evs = sim.cycle(vec![fail(), fail()]);
        // Both flip down; internet's alert is suppressed as implied by LAN.
        assert_eq!(
            kinds(&evs),
            vec![("lan", "down", true), ("internet", "down", false)]
        );

        // LAN recovers while the internet stays down: the internet outage now
        // stands on its own, so the overdue alert fires as still_down.
        sim.cycle(vec![ok(2.0), fail()]);
        sim.cycle(vec![ok(2.0), fail()]);
        let evs = sim.cycle(vec![ok(2.0), fail()]);
        assert_eq!(
            kinds(&evs),
            vec![("lan", "up", true), ("internet", "still_down", true)]
        );

        // No outage double-count: internet recovery reports the full duration.
        sim.cycle(vec![ok(2.0), ok(20.0)]);
        sim.cycle(vec![ok(2.0), ok(20.0)]);
        let evs = sim.cycle(vec![ok(2.0), ok(20.0)]);
        assert_eq!(kinds(&evs), vec![("internet", "up", true)]);
        assert_eq!(evs[0].duration_secs, Some(6 * INTERVAL));
    }

    #[test]
    fn degraded_alerts_respect_cooldown_and_pair_recovery_notification() {
        // window of 5 with a 30% threshold: one failure (25% of 4, 20% of 5)
        // stays quiet, two failures (40%) trip it.
        let mut sim = Sim::new(cfg(&format!(
            "window_samples = 5\n[degraded]\nloss_pct = 30.0\n{INET}"
        )));
        for _ in 0..3 {
            assert!(sim.cycle(vec![ok(20.0)]).is_empty());
        }
        sim.cycle(vec![fail()]);
        let evs = sim.cycle(vec![fail()]);
        assert_eq!(kinds(&evs), vec![("internet", "degraded", true)]);

        // Enough clean cycles to flush the failures out of the window.
        let mut end = Vec::new();
        for _ in 0..5 {
            end.extend(sim.cycle(vec![ok(20.0)]));
        }
        assert_eq!(kinds(&end), vec![("internet", "degraded_end", true)]);

        // Degrades again within the 30 min cooldown: recorded, not notified,
        // and the paired "back to normal" is silent too.
        sim.cycle(vec![fail()]);
        let evs = sim.cycle(vec![fail()]);
        assert_eq!(kinds(&evs), vec![("internet", "degraded", false)]);
        let mut end = Vec::new();
        for _ in 0..5 {
            end.extend(sim.cycle(vec![ok(20.0)]));
        }
        assert_eq!(kinds(&end), vec![("internet", "degraded_end", false)]);
    }

    #[test]
    fn no_false_degraded_right_after_outage_recovery() {
        let mut sim = Sim::new(cfg(INET));
        sim.cycle(vec![ok(20.0)]);
        for _ in 0..2 {
            sim.cycle(vec![fail()]);
        }
        let evs = sim.cycle(vec![fail()]);
        assert_eq!(kinds(&evs), vec![("internet", "down", true)]);

        sim.cycle(vec![ok(20.0)]);
        sim.cycle(vec![ok(20.0)]);
        let evs = sim.cycle(vec![ok(20.0)]);
        // Only the recovery: the failure-heavy window must not read as loss.
        assert_eq!(kinds(&evs), vec![("internet", "up", true)]);
        let evs = sim.cycle(vec![ok(20.0)]);
        assert!(evs.is_empty(), "unexpected events: {:?}", kinds(&evs));
    }

    #[test]
    fn host_alerts_individually_with_duration() {
        let mut sim = Sim::new(cfg(&format!("{LAN}{NAS}")));
        sim.cycle(vec![ok(2.0), fail()]);
        sim.cycle(vec![ok(2.0), fail()]);
        let evs = sim.cycle(vec![ok(2.0), fail()]);
        assert_eq!(kinds(&evs), vec![("host", "down", true)]);
        assert_eq!(evs[0].target.as_deref(), Some("nas"));

        sim.cycle(vec![ok(2.0), ok(9.0)]);
        sim.cycle(vec![ok(2.0), ok(9.0)]);
        let evs = sim.cycle(vec![ok(2.0), ok(9.0)]);
        assert_eq!(kinds(&evs), vec![("host", "up", true)]);
        assert_eq!(evs[0].duration_secs, Some(3 * INTERVAL));
    }

    #[test]
    fn host_suppressed_by_lan_down_then_catches_up() {
        let mut sim = Sim::new(cfg(&format!("{LAN}{NAS}")));
        sim.cycle(vec![fail(), fail()]);
        sim.cycle(vec![fail(), fail()]);
        let evs = sim.cycle(vec![fail(), fail()]);
        assert_eq!(
            kinds(&evs),
            vec![("lan", "down", true), ("host", "down", false)]
        );

        sim.cycle(vec![ok(2.0), fail()]);
        sim.cycle(vec![ok(2.0), fail()]);
        let evs = sim.cycle(vec![ok(2.0), fail()]);
        assert_eq!(
            kinds(&evs),
            vec![("lan", "up", true), ("host", "still_down", true)]
        );
    }

    #[test]
    fn silent_host_records_history_but_never_notifies() {
        let quiet = NAS.replace(
            "addr = \"192.168.1.40\"",
            "addr = \"192.168.1.40\"\nalert = false",
        );
        let mut sim = Sim::new(cfg(&quiet));
        sim.cycle(vec![fail()]);
        sim.cycle(vec![fail()]);
        let evs = sim.cycle(vec![fail()]);
        assert_eq!(kinds(&evs), vec![("host", "down", false)]);
        // No still_down catch-up for a silent host.
        assert!(sim.cycle(vec![fail()]).is_empty());
        sim.cycle(vec![ok(1.0)]);
        sim.cycle(vec![ok(1.0)]);
        let evs = sim.cycle(vec![ok(1.0)]);
        assert_eq!(kinds(&evs), vec![("host", "up", false)]);
    }

    #[test]
    fn resume_mid_outage_recovers_without_double_counting() {
        let outage_start = BASE_TS - 600;
        let resume = ResumeState {
            targets: vec![ResumeTarget {
                up: false,
                down_since: Some(outage_start),
                notified_down: true,
            }],
            layers: HashMap::from([(
                Layer::Internet,
                ResumeLayer {
                    down_since: outage_start,
                    notified_down: true,
                },
            )]),
        };
        let mut sim = Sim::resumed(cfg(INET), Some(resume));

        // Still down: no fresh "down" event, the outage is already on record.
        assert!(sim.cycle(vec![fail()]).is_empty());

        // Recovery alert carries the full duration from before the restart.
        sim.cycle(vec![ok(20.0)]);
        sim.cycle(vec![ok(20.0)]);
        let evs = sim.cycle(vec![ok(20.0)]);
        assert_eq!(kinds(&evs), vec![("internet", "up", true)]);
        let dur = evs[0].duration_secs.unwrap();
        assert_eq!(dur, (BASE_TS + 4 * INTERVAL) - outage_start);
    }

    #[test]
    fn resume_unnotified_outage_sends_catchup_alert() {
        let resume = ResumeState {
            targets: vec![ResumeTarget {
                up: false,
                down_since: Some(BASE_TS - 300),
                notified_down: false,
            }],
            layers: HashMap::from([(
                Layer::Internet,
                ResumeLayer {
                    down_since: BASE_TS - 300,
                    notified_down: false,
                },
            )]),
        };
        let mut sim = Sim::resumed(cfg(INET), Some(resume));
        // The pre-restart down was never notified (e.g. queued and lost):
        // the catch-up pass owes the user an alert.
        let evs = sim.cycle(vec![fail()]);
        assert_eq!(kinds(&evs), vec![("internet", "still_down", true)]);
        assert!(sim.cycle(vec![fail()]).is_empty());
    }

    #[test]
    fn snapshot_reflects_verdict_and_layers() {
        let mut sim = Sim::new(cfg(&format!("{LAN}{INET}")));
        sim.cycle(vec![ok(2.0), ok(25.0)]);
        let snap = sim.engine.snapshot(sim.ts);
        assert_eq!(snap.verdict_status, Status::Up);
        assert!(snap.verdict.starts_with("Internet OK"));
        assert_eq!(snap.layers.len(), 2);

        for _ in 0..3 {
            sim.cycle(vec![ok(2.0), fail()]);
        }
        let snap = sim.engine.snapshot(sim.ts);
        assert_eq!(snap.verdict_status, Status::Down);
        assert!(snap.verdict.contains("UPLINK OUTAGE"), "{}", snap.verdict);
    }
}
