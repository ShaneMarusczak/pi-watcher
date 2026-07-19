use crate::engine::Layer;
use crate::probes::ProbeSpec;
use anyhow::{bail, Context};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Deserialize, Clone, Debug)]
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
#[derive(Deserialize, Clone, Debug)]
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

#[rustfmt::skip]
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

#[derive(Deserialize, Clone, Debug)]
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

#[derive(Deserialize, Clone, Debug)]
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
#[derive(Deserialize, Clone, Debug)]
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

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Ping,
    Dns,
}

#[derive(Deserialize, Clone, Debug)]
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
                if ip.is_ipv6() {
                    bail!(
                        "target '{}': IPv6 addresses are not supported (probes are IPv4-only)",
                        self.name
                    );
                }
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
                if sa.is_ipv6() {
                    bail!(
                        "target '{}': IPv6 addresses are not supported (probes are IPv4-only)",
                        self.name
                    );
                }
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
        Self::parse(&text).with_context(|| format!("parsing {path}"))
    }

    /// Upper bounds exist so that later arithmetic on these values
    /// (hours * 3600, days * 86400, ...) can never overflow a u64.
    pub fn parse(text: &str) -> anyhow::Result<Config> {
        let cfg: Config = toml::from_str(text)?;
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
        if !(5..=86400).contains(&cfg.interval_secs) {
            bail!("interval_secs must be between 5 and 86400");
        }
        if !(3..=10_000).contains(&cfg.window_samples) {
            bail!("window_samples must be between 3 and 10000");
        }
        if cfg.probe_timeout_secs == 0 || cfg.probe_timeout_secs >= cfg.interval_secs {
            bail!("probe_timeout_secs must be >= 1 and < interval_secs");
        }
        if cfg.fail_threshold == 0 || cfg.recover_threshold == 0 {
            bail!("fail_threshold and recover_threshold must be >= 1");
        }
        if !(1..=3650).contains(&cfg.retention_days) {
            bail!("retention_days must be between 1 and 3650");
        }
        if cfg.degraded.cooldown_mins > 525_600 {
            bail!("degraded.cooldown_mins must be <= 525600 (one year)");
        }
        if !(cfg.degraded.loss_pct.is_finite() && cfg.degraded.loss_pct > 0.0) {
            bail!("degraded.loss_pct must be a positive number");
        }
        if !(cfg.degraded.latency_ms.is_finite() && cfg.degraded.latency_ms > 0.0) {
            bail!("degraded.latency_ms must be a positive number");
        }
        for tile in &cfg.tiles {
            let (hours, target) = match tile {
                Tile::Uptime { hours, target, .. } => (*hours, target.as_ref()),
                Tile::Outages { hours, .. } | Tile::Downtime { hours, .. } => (*hours, None),
                Tile::Target { target, .. } => (1, Some(target)),
            };
            if !(1..=87_600).contains(&hours) {
                bail!("tile hours must be between 1 and 87600 (10 years)");
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[[targets]]
name = "router"
layer = "lan"
kind = "ping"
addr = "192.168.1.1"
"#;

    #[test]
    fn example_config_stays_valid() {
        Config::parse(include_str!("../config.example.toml")).unwrap();
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let cfg = Config::parse(MINIMAL).unwrap();
        assert_eq!(cfg.interval_secs, 30);
        assert_eq!(cfg.fail_threshold, 3);
        assert_eq!(cfg.tiles.len(), 5);
    }

    #[test]
    fn ipv6_targets_rejected() {
        let toml = r#"
[[targets]]
name = "cf"
layer = "internet"
kind = "ping"
addr = "2606:4700:4700::1111"
"#;
        let err = Config::parse(toml).unwrap_err().to_string();
        assert!(err.contains("IPv6"), "unexpected error: {err}");
    }

    #[test]
    fn zero_thresholds_rejected() {
        let err = Config::parse(&format!("fail_threshold = 0\n{MINIMAL}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("fail_threshold"), "unexpected error: {err}");
    }

    #[test]
    fn duplicate_target_names_rejected() {
        let toml = format!(
            "{MINIMAL}\n{}",
            MINIMAL.replace("layer = \"lan\"", "layer = \"host\"")
        );
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "unexpected error: {err}");
    }

    #[test]
    fn tile_with_unknown_target_rejected() {
        let toml = format!("{MINIMAL}\n[[tiles]]\nkind = \"target\"\ntarget = \"nas\"\n");
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("unknown target"), "unexpected error: {err}");
    }

    #[test]
    fn absurd_tile_hours_rejected() {
        let toml = format!("{MINIMAL}\n[[tiles]]\nkind = \"uptime\"\nhours = 9000000\n");
        assert!(Config::parse(&toml).is_err());
    }

    #[test]
    fn zero_retention_rejected() {
        assert!(Config::parse(&format!("retention_days = 0\n{MINIMAL}")).is_err());
    }
}
