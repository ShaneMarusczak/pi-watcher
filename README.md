# pi-watcher

A single-binary Rust network watcher for a Raspberry Pi (or any small Linux
box). It answers one question most home monitoring tools fumble: **when the
internet feels bad, which part of the network is actually at fault — and how
often does it happen?**

Built with flaky WAN links in mind (cellular/5G home internet especially,
where the link degrades more often than it cleanly dies), but every probe,
threshold, alert, and dashboard tile is driven by one TOML config.

- **Layered probing with attribution** — every failure is blamed on the right
  layer: your LAN, your WAN gateway, the internet at large, or DNS.
- **History, not just alerts** — every probe lands in SQLite, so you can ask
  "does the link degrade every evening?" weeks later.
- **ntfy notifications** — outage, recovery (with duration), and degradation
  alerts to your phone via [ntfy](https://ntfy.sh). Undeliverable messages are
  queued and retried, so the alert about an outage survives the outage itself.
- **Restart-proof state** — on startup the watcher rehydrates target and
  layer state from the database, so a crash or redeploy mid-outage doesn't
  double-count the outage, lose its duration, or skip the recovery alert.
  (Notifications queued in memory but not yet delivered don't survive a
  restart; the catch-up logic re-alerts for anything still down and
  unannounced.)
- **Self-contained web dashboard** — live status, uptime/outage tiles,
  latency and loss charts (6h–30d), event log. No CDN dependencies, so it
  works while the internet is down.
- **Watched hosts** — add any machine (NAS, printer, server) and get
  individual down/recovered alerts that never pollute the internet verdict.

## How it works

Each cycle (default 30s), pi-watcher probes a ladder of targets you define,
one layer at a time:

| layer | typical target | a failure here means |
|---|---|---|
| `lan` | your router | the Pi or local network is the problem |
| `gateway` | the hop past your router (e.g. an ISP/cellular gateway) | the path to the WAN device is broken |
| `internet` | public anchors like `1.1.1.1`, `8.8.8.8` | traffic isn't crossing the uplink |
| `dns` | your resolver (e.g. a Pi-hole), port 53 | names aren't resolving |
| `host` | anything else you care about | that one machine is down |

Attribution falls out of the ladder: **internet down while the gateway
answers = the uplink is at fault**, and the alert says so. When a lower layer
is down, alerts for the layers above it are suppressed (still recorded)
because they're implied — and if the lower layer recovers while a higher one
stays broken, the overdue alert fires then.

The internet layer aggregates its anchors with a **minimum**: only a problem
on the shared path hurts every anchor at once, so one anchor having a bad day
never raises a false alarm.

### Alert types

- **Down / recovered** — after N consecutive failed cycles (default 3);
  recovery includes the outage duration.
- **Degraded / back to normal** — the link is up but hurting: packet loss or
  rolling-median latency over your thresholds, judged on a sliding window
  (defaults: 20% / 250 ms over 5 minutes), with a configurable cooldown.
- **Host down / recovered** — per watched host, suppressed only when the LAN
  itself is down; `alert = false` records history silently.

## Quick start

Needs Rust 1.87 or newer.

```sh
cargo build --release          # on the Pi, or cross-compile (see below)
sudo mkdir -p /etc/pi-watcher
sudo cp config.example.toml /etc/pi-watcher/config.toml
sudo nano /etc/pi-watcher/config.toml    # set your IPs and ntfy topic
sudo cp target/release/pi-watcher /usr/local/bin/
sudo cp deploy/pi-watcher.service /etc/systemd/system/
sudo systemctl enable --now pi-watcher
```

Subscribe to your topic in the ntfy app; within a cycle you'll get a startup
message proving the alert path works, and the dashboard is on port 8080.

The systemd unit runs unprivileged (`DynamicUser`) with `CAP_NET_RAW` for
ICMP, and keeps the database in `/var/lib/pi-watcher/`. It also waits for
`time-sync.target`: Pis have no hardware clock, and samples stamped before
NTP sync would land in history with a bogus timestamp. Run
`sudo systemctl enable systemd-time-wait-sync` once to make that wait real.

**Cross-compiling** from a desktop with
[cross](https://github.com/cross-rs/cross):
`cross build --release --target aarch64-unknown-linux-gnu` (64-bit ARM) or
`--target armv7-unknown-linux-gnueabihf` (32-bit).

### Finding your IPs

- Your router's IP: `ip route | head -1` (the `default via` address).
- The gateway layer is the hop *past* your router — hop 2 of
  `traceroute -n 1.1.1.1`. If you have a single router straight to the
  internet, delete the `gateway` target; the ladder works with any subset of
  layers.
- Give anything you probe a DHCP reservation so the IPs stay true.

## Configuration

Everything lives in one TOML file — [config.example.toml](config.example.toml)
documents every key and ships with placeholder addresses. Highlights:

- **Targets**: any number, each `ping` (ICMP) or `dns` (a real A-record query
  against a specific server), assigned to a layer. Addresses must be IPv4 —
  the probes are IPv4-only, and the config loader rejects IPv6 rather than
  letting a target fail silently forever.
- **Tuning**: probe interval, failure/recovery hysteresis, rolling-window
  size, degradation thresholds and cooldown, retention.
- **Tiles**: the dashboard's stat row is built from `[[tiles]]` entries —
  uptime/outages/downtime over any window, per-target uptime, or a live
  latency tile for any target. Omit the section for a sensible default row.
- **ntfy**: server URL (ntfy.sh or self-hosted), topic, optional access
  token, optional click-through URL to open your dashboard from an alert.

## Storage

SQLite in WAL mode with `synchronous=NORMAL` and a capped journal — gentle on
SD cards. Raw samples are pruned after `retention_days` (default 90); events
are tiny and kept forever, because they're the long-term story. The database
is queryable directly:

```sh
sqlite3 /var/lib/pi-watcher/watcher.db \
  "SELECT datetime(ts,'unixepoch','localtime'), message FROM events ORDER BY ts DESC LIMIT 20"
```

## Security notes

- **Never commit your real config.** The ntfy topic acts as a password:
  anyone who has it can read your outage alerts and push fake notifications.
  The `.gitignore` here refuses `config.toml` for exactly this reason.
- The dashboard has **no authentication** — keep it LAN-only; don't
  port-forward it.
- The database reveals when your home loses connectivity; treat it as
  private.
- Uptime numbers measure *observed* cycles: time the watcher itself was off
  is a gap in the data, not counted as downtime.

## License

MIT — see [LICENSE](LICENSE).
