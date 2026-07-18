mod config;
mod monitor;
mod notify;
mod probes;
mod store;
mod web;

use std::sync::Arc;

fn usage() -> ! {
    eprintln!("usage: pi-watcher [--config <path>]   (default: ./config.toml)");
    std::process::exit(2);
}

fn config_path() -> String {
    let mut args = std::env::args().skip(1);
    let mut path: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => path = Some(args.next().unwrap_or_else(|| usage())),
            "--help" | "-h" => usage(),
            other if path.is_none() && !other.starts_with('-') => path = Some(other.to_string()),
            _ => usage(),
        }
    }
    path.unwrap_or_else(|| "config.toml".to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = config_path();
    let cfg = config::Config::load(&path)?;
    println!(
        "[pi-watcher] {} targets, probing every {}s (config: {path})",
        cfg.targets.len(),
        cfg.interval_secs
    );

    let store = store::Store::open(&cfg.db_path)?;
    let web_store = store::Store::open(&cfg.db_path)?;
    let notifier = notify::Notifier::new(cfg.ntfy.clone());

    let shared = Arc::new(web::Shared::new(web_store, &cfg));
    tokio::spawn(web::serve(cfg.web.listen.clone(), shared.clone()));

    monitor::run(cfg, store, notifier, shared).await
}
