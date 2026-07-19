use crate::config::NtfyConfig;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct Msg {
    pub title: String,
    pub body: String,
    /// ntfy priority: 1 min .. 5 urgent
    pub priority: u8,
    pub tags: &'static str,
}

/// Queues messages and retries delivery until it succeeds. This matters here:
/// when the cellular link is down, the "down" alert can't leave the house -
/// it must survive until the link comes back so the phone still gets the story.
#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::UnboundedSender<Msg>,
}

const MAX_QUEUED: usize = 50;
const RETRY_SECS: u64 = 30;

impl Notifier {
    pub fn new(cfg: NtfyConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(worker(cfg, rx));
        Notifier { tx }
    }

    pub fn send(&self, msg: Msg) {
        let _ = self.tx.send(msg);
    }
}

enum DeliverError {
    /// Transport problems and server-side hiccups: worth retrying, the whole
    /// point of the queue.
    Retry(String),
    /// The server understood us and said no (bad token, missing topic, ...).
    /// Retrying would block the queue forever behind a message that can
    /// never be delivered.
    Permanent(String),
}

async fn worker(cfg: NtfyConfig, mut rx: mpsc::UnboundedReceiver<Msg>) {
    // Client construction failing (broken TLS backend) must not kill the
    // worker silently: fall back to log-only delivery.
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("[ntfy] cannot create HTTP client ({e}) - notifications will be logged only");
            None
        }
    };
    let enabled = !cfg.topic.is_empty() && http.is_some();
    if http.is_some() && cfg.topic.is_empty() {
        println!("[ntfy] no topic configured - notifications will be logged only");
    }
    let url = format!("{}/{}", cfg.url.trim_end_matches('/'), cfg.topic);
    let mut queue: VecDeque<Msg> = VecDeque::new();

    loop {
        if queue.is_empty() {
            match rx.recv().await {
                Some(m) => queue.push_back(m),
                None => return,
            }
        }
        while let Ok(m) = rx.try_recv() {
            queue.push_back(m);
        }
        while queue.len() > MAX_QUEUED {
            queue.pop_front();
        }

        while let Some(m) = queue.front() {
            let (true, Some(http)) = (enabled, &http) else {
                println!("[ntfy skipped] {}: {}", m.title, m.body);
                queue.pop_front();
                continue;
            };
            match deliver(http, &cfg, &url, m).await {
                Ok(()) => {
                    println!("[ntfy] sent: {}", m.title);
                    queue.pop_front();
                }
                Err(DeliverError::Permanent(e)) => {
                    eprintln!(
                        "[ntfy] DROPPING message '{}' ({e}) - check the ntfy url/topic/token",
                        m.title
                    );
                    queue.pop_front();
                }
                Err(DeliverError::Retry(e)) => {
                    eprintln!(
                        "[ntfy] delivery failed ({e}); {} message(s) queued, retrying in {RETRY_SECS}s",
                        queue.len()
                    );
                    break;
                }
            }
        }

        if !queue.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(RETRY_SECS)) => {}
                m = rx.recv() => match m {
                    Some(m) => queue.push_back(m),
                    None => return,
                },
            }
        }
    }
}

async fn deliver(
    http: &reqwest::Client,
    cfg: &NtfyConfig,
    url: &str,
    m: &Msg,
) -> Result<(), DeliverError> {
    let mut req = http
        .post(url)
        .header("Title", m.title.clone())
        .header("Priority", m.priority.to_string())
        .header("Tags", m.tags)
        .body(m.body.clone());
    if let Some(token) = &cfg.token {
        req = req.bearer_auth(token);
    }
    if let Some(click) = &cfg.click_url {
        req = req.header("Click", click.clone());
    }
    let resp = req
        .send()
        .await
        .map_err(|e| DeliverError::Retry(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let msg = format!("ntfy returned {status}");
    if status.is_server_error() || status.as_u16() == 429 || status.as_u16() == 408 {
        Err(DeliverError::Retry(msg))
    } else {
        Err(DeliverError::Permanent(msg))
    }
}
