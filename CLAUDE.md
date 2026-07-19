# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build
cargo build --release          # panic=abort, opt-level=z, lto

# Test (engine state machine, config validation, store queries)
cargo test
cargo test <test_name>

# Lint (Clippy warns on panic/unwrap_used/expect_used; CI runs -D warnings)
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Cross-compile for a Pi
cross build --release --target aarch64-unknown-linux-gnu
```

## Architecture

A single binary: probe a ladder of network targets on a fixed interval,
attribute failures to the right layer, record everything in SQLite, alert
via ntfy, and serve a dashboard.

- **`engine.rs`** — the whole monitoring judgement, pure and synchronous:
  per-target hysteresis windows, layer status in rank order
  (lan → gateway → internet → dns, plus per-target `host`), alert
  suppression when a lower layer is down, catch-up `still_down` alerts when
  it recovers, degraded detection with cooldown, and `ResumeState` for
  rehydrating after a restart. `evaluate(ts, mono, results) -> Vec<PendingEvent>`
  takes wall time for records and monotonic time for durations (NTP steps on
  RTC-less Pis must not distort durations). All behavior tests live here —
  drive the `Sim` helper cycle by cycle.
- **`monitor.rs`** — the async loop around the engine: spawns probes,
  persists samples/events, sends notifications, publishes the web snapshot,
  prunes, handles signals. Loads `ResumeState` from the store at startup
  (skipped if the last sample is older than 10 intervals).
- **`probes.rs`** — ICMP ping (shared surge-ping client behind an `Arc`;
  its `Drop` kills the reply map for every clone, so never clone the bare
  client) and a hand-rolled UDP DNS A-query. IPv4 only, enforced at config
  load.
- **`store.rs`** — SQLite (WAL, `synchronous=NORMAL` for SD cards).
  `samples` share one `ts` per cycle so `GROUP BY ts` works; `events` are
  kept forever and carry a `target` column (nullable, migrated in place) for
  per-host resume.
- **`notify.rs`** — queued ntfy delivery with retries. 4xx (except 408/429)
  is permanent: drop the message loudly rather than block the queue forever.
- **`web.rs`** — axum routes + embedded `assets/index.html` (no CDN, works
  offline). DB queries run under `spawn_blocking`. History is clamped to
  `retention_days`.
- **`config.rs`** — one TOML file, `deny_unknown_fields` everywhere,
  validation bounds chosen so downstream arithmetic can't overflow.
  `Config::parse` is the testable entry; `load` adds file I/O.

## Conventions

- Clippy `panic`/`unwrap_used`/`expect_used` warn crate-wide; tests opt out
  via module-level `#[allow]`. Prefer `?`, `let-else`, or explicit fallbacks.
- Never commit a real `config.toml` (the ntfy topic is a credential);
  `config.example.toml` is the documented template and is parse-tested.
- `deploy/pi-watcher.service` is the reference deployment: `DynamicUser`,
  `CAP_NET_RAW`, waits on `time-sync.target`.
