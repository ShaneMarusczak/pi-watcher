use crate::config::{Config, Tile};
use crate::monitor::{unix_now, Layer, Snapshot};
use crate::store::Store;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

pub struct Shared {
    pub snapshot: RwLock<Option<Snapshot>>,
    pub db: Mutex<Store>,
    pub targets: Vec<(String, Layer)>,
    pub tiles: Vec<Tile>,
    pub interval_secs: u64,
}

impl Shared {
    pub fn new(store: Store, cfg: &Config) -> Self {
        Shared {
            snapshot: RwLock::new(None),
            db: Mutex::new(store),
            targets: cfg
                .targets
                .iter()
                .map(|t| (t.name.clone(), t.layer))
                .collect(),
            tiles: cfg.tiles.clone(),
            interval_secs: cfg.interval_secs,
        }
    }

    fn internet_targets(&self) -> Vec<String> {
        self.targets
            .iter()
            .filter(|(_, l)| *l == Layer::Internet)
            .map(|(n, _)| n.clone())
            .collect()
    }
}

pub async fn serve(listen: String, shared: Arc<Shared>) {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(api_status))
        .route("/api/history", get(api_history))
        .route("/api/events", get(api_events))
        .route("/api/stats", get(api_stats))
        .with_state(shared);
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[web] cannot bind {listen}: {e}");
            std::process::exit(1);
        }
    };
    println!("[web] listening on http://{listen}");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("[web] server error: {e}");
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

async fn api_status(State(s): State<Arc<Shared>>) -> Json<Option<Snapshot>> {
    Json(s.snapshot.read().await.clone())
}

#[derive(Deserialize)]
struct HistoryQ {
    hours: Option<f64>,
}

async fn api_history(State(s): State<Arc<Shared>>, Query(q): Query<HistoryQ>) -> Json<Value> {
    let hours = q.hours.unwrap_or(24.0).clamp(0.25, 24.0 * 90.0);
    let from = unix_now().saturating_sub((hours * 3600.0) as u64);
    // ~240 points regardless of range, never finer than the probe interval.
    let bucket = ((hours * 3600.0 / 240.0) as u64)
        .max(s.interval_secs)
        .max(30);

    let rows = match s.db.lock().unwrap().history(from, bucket) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[web] history query failed: {e}");
            Vec::new()
        }
    };

    let series: Vec<Value> = s
        .targets
        .iter()
        .map(|(name, layer)| {
            let points: Vec<Value> = rows
                .iter()
                .filter(|r| &r.target == name)
                .map(|r| {
                    let loss = if r.total > 0 {
                        r.fails as f64 / r.total as f64 * 100.0
                    } else {
                        0.0
                    };
                    json!([r.bucket, r.avg_ms, loss])
                })
                .collect();
            json!({ "target": name, "layer": layer, "points": points })
        })
        .collect();

    Json(json!({ "from": from, "bucket_secs": bucket, "series": series }))
}

#[derive(Deserialize)]
struct EventsQ {
    limit: Option<u32>,
}

async fn api_events(State(s): State<Arc<Shared>>, Query(q): Query<EventsQ>) -> Json<Value> {
    let limit = q.limit.unwrap_or(50).min(500);
    let events = match s.db.lock().unwrap().events(limit) {
        Ok(evs) => evs
            .iter()
            .map(|e| {
                json!({
                    "ts": e.ts,
                    "layer": e.layer,
                    "kind": e.kind,
                    "message": e.message,
                    "duration_secs": e.duration_secs,
                })
            })
            .collect(),
        Err(e) => {
            eprintln!("[web] events query failed: {e}");
            Vec::new()
        }
    };
    Json(json!({ "events": events }))
}

fn window_label(hours: u64) -> String {
    if hours >= 24 && hours.is_multiple_of(24) {
        format!("{} d", hours / 24)
    } else {
        format!("{} h", hours)
    }
}

/// The tiles row, computed from the configured tile specs. Target tiles carry
/// only the spec; the page joins them with the live snapshot it already polls.
async fn api_stats(State(s): State<Arc<Shared>>) -> Json<Value> {
    let now = unix_now();
    let db = s.db.lock().unwrap();
    let tiles: Vec<Value> = s
        .tiles
        .iter()
        .map(|tile| match tile {
            Tile::Uptime { hours, label, target } => {
                let names = match target {
                    Some(t) => vec![t.clone()],
                    None => s.internet_targets(),
                };
                let value = db
                    .uptime(now.saturating_sub(hours * 3600), &names)
                    .ok()
                    .flatten()
                    .map(|u| u * 100.0);
                let label = label.clone().unwrap_or_else(|| match target {
                    Some(t) => format!("{t} uptime \u{b7} {}", window_label(*hours)),
                    None => format!("Uptime \u{b7} {}", window_label(*hours)),
                });
                json!({ "kind": "uptime", "label": label, "value": value })
            }
            Tile::Outages { hours, label } => {
                let (outages, _) = db
                    .outage_stats(now.saturating_sub(hours * 3600))
                    .unwrap_or((0, 0));
                let label = label
                    .clone()
                    .unwrap_or_else(|| format!("Outages \u{b7} {}", window_label(*hours)));
                json!({ "kind": "outages", "label": label, "value": outages })
            }
            Tile::Downtime { hours, label } => {
                let (_, downtime) = db
                    .outage_stats(now.saturating_sub(hours * 3600))
                    .unwrap_or((0, 0));
                let label = label
                    .clone()
                    .unwrap_or_else(|| format!("Downtime \u{b7} {}", window_label(*hours)));
                json!({ "kind": "downtime", "label": label, "value": downtime })
            }
            Tile::Target { target, label } => {
                let label = label.clone().unwrap_or_else(|| target.clone());
                json!({ "kind": "target", "label": label, "target": target })
            }
        })
        .collect();
    Json(json!({ "tiles": tiles }))
}
