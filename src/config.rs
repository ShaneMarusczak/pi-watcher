use crate::monitor::Layer;
use crate::probes::ProbeSpec;
use anyhow::{bail, Context};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "d_interval")]
    pub interval_secs: u64,
    #[serde(default = "d_db_path")]
    pub db_path: String,
    #[serde(default = "d_three")]
    pub fail_threshold: u32,
    #[serde(default = "d_three")]
    pub recover_threshold: u32,
    #[serde(default = "d_window")]
    pub window_samples: usize,
    #[serde(default = "d_timeout")]
    pub probe_timeout_secs: u64,
    #[serde(default = "d_retention")]
    pub retention_days: u64,
    #[serde(default = "d_true")]
    pub startup_message: bool,
    #[serde(default)]
    pub ntfy: NtfyConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub degraded: DegradedConfig,
    /// Dashboard tiles row. Omitted = the default internet-uptime set.
    #[serde(default = "default_tiles")]
    pub tiles: Vec<Tile>,
    pub targets: Vec<Target>,
}

/// One tile on the dashboard. `uptime`/`outages`/`downtime` are computed from
/// history; `target` shows the live state of one target by name.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "lowercase")]
pub enum Tile {
    Uptime {
        #[serde(default = "d_day")]
        hours: u64,
        #[serde(default)]
        label: Option<String>,
        /// Uptime of this one target instead of the internet layer.
        #[serde(default)]
        target: Option<String>,
    },
    Outages {
        #[serde(default = "d_week")]
        hours: u64,
        #[serde(default)]
        label: Option<String>,
    },
    Downtime {
        #[serde(default = "d_week")]
        hours: u64,
        #[serde(default)]
        label: Option<String>,
    },
    Target {
        target: String,
        #[serde(default)]
        label: Option<String>,
    },
}

fn d_day() -> u64 {
    24
}
fn d_week() -> u64 {
    168
}

pub fn default_tiles() -> Vec<Tile> {
    vec![
        Tile::Uptime { hours: 24, label: None, target: None },
        Tile::Uptime { hours: 168, label: None, target: None },
        Tile::Uptime { hours: 720, label: None, target: None },
        Tile::Outages { hours: 168, label: None },
        Tile::Downtime { hours: 168, label: None },
    ]
}

fn d_interval() -> u64 {
    30
}
fn d_db_path() -> String {
    "watcher.db".into()
}
fn d_three() -> u32 {
    3
}
fn d_window() -> usize {
    10
}
fn d_timeout() -> u64 {
    3
}
fn d_retention() -> u64 {
    90
}
fn d_true() -> bool {
    true
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    #[serde(default = "d_ntfy_url")]
    pub url: String,
    #[serde(default)]
    pub topic: String,
    #[serde(default)]
    pub token: Option<String>,
    /// Sent as the ntfy Click header: tapping the notification opens this URL
    /// (e.g. the status page, http://pi.local:8080).
    #[serde(default)]
    pub click_url: Option<String>,
}

fn d_ntfy_url() -> String {
    "https://ntfy.sh".into()
}

impl Default for NtfyConfig {
    fn default() -> Self {
        Self {
            url: d_ntfy_url(),
            topic: String::new(),
            token: None,
            click_url: None,
        }
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    #[serde(default = "d_listen")]
    pub listen: String,
}

fn d_listen() -> String {
    "0.0.0.0:8080".into()
}

impl Default for WebConfig {
    fn default() -> Self {
        Self { listen: d_listen() }
    }
}

/// Degradation detection applies to the internet layer only: sustained packet
/// loss or elevated rolling-median latency while the link is still nominally up.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DegradedConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_loss")]
    pub loss_pct: f64,
    #[serde(default = "d_lat")]
    pub latency_ms: f64,
    #[serde(default = "d_cooldown")]
    pub cooldown_mins: u64,
}

fn d_loss() -> f64 {
    20.0
}
fn d_lat() -> f64 {
    250.0
}
fn d_cooldown() -> u64 {
    30
}

impl Default for DegradedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            loss_pct: d_loss(),
            latency_ms: d_lat(),
            cooldown_mins: d_cooldown(),
        }
    }
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Ping,
    Dns,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub layer: Layer,
    pub kind: TargetKind,
    pub addr: String,
    #[serde(default)]
    pub query: Option<String>,
    /// For host-layer targets: send down/up notifications. History is
    /// recorded either way. Ladder layers alert at layer level and ignore this.
    #[serde(default = "d_true")]
    pub alert: bool,
}

impl Target {
    pub fn probe_spec(&self) -> anyhow::Result<ProbeSpec> {
        match self.kind {
            TargetKind::Ping => {
                let ip: IpAddr = self.addr.parse().with_context(|| {
                    format!(
                        "target '{}': addr '{}' is not an IP address",
                        self.name, self.addr
                    )
                })?;
                Ok(ProbeSpec::Ping(ip))
            }
            TargetKind::Dns => {
                let sa: SocketAddr = match self.addr.parse() {
                    Ok(sa) => sa,
                    Err(_) => {
                        let ip: IpAddr = self.addr.parse().with_context(|| {
                            format!(
                                "target '{}': addr '{}' is not an IP or IP:port",
                                self.name, self.addr
                            )
                        })?;
                        SocketAddr::new(ip, 53)
                    }
                };
                let query = self
                    .query
                    .clone()
                    .unwrap_or_else(|| "www.google.com".to_string());
                Ok(ProbeSpec::Dns(sa, query))
            }
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading config file {path}"))?;
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {path}"))?;
        if cfg.targets.is_empty() {
            bail!("config has no [[targets]]");
        }
        let mut names = std::collections::HashSet::new();
        for t in &cfg.targets {
            if !names.insert(t.name.clone()) {
                bail!("duplicate target name '{}'", t.name);
            }
            t.probe_spec()?;
        }
        if cfg.interval_secs < 5 {
            bail!("interval_secs must be >= 5");
        }
        if cfg.window_samples < 3 {
            bail!("window_samples must be >= 3");
        }
        if cfg.probe_timeout_secs == 0 || cfg.probe_timeout_secs >= cfg.interval_secs {
            bail!("probe_timeout_secs must be >= 1 and < interval_secs");
        }
        for tile in &cfg.tiles {
            let (hours, target) = match tile {
                Tile::Uptime { hours, target, .. } => (*hours, target.as_ref()),
                Tile::Outages { hours, .. } | Tile::Downtime { hours, .. } => (*hours, None),
                Tile::Target { target, .. } => (1, Some(target)),
            };
            if hours == 0 {
                bail!("tile hours must be >= 1");
            }
            if let Some(t) = target {
                if !names.contains(t) {
                    bail!("tile references unknown target '{t}'");
                }
            }
        }
        Ok(cfg)
    }
}
