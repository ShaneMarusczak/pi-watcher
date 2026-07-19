use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use surge_ping::{Client, Config as PingConfig, PingIdentifier, PingSequence, ICMP};

#[derive(Clone)]
pub enum ProbeSpec {
    Ping(IpAddr),
    /// DNS A-record lookup against a specific server: (server, query name).
    Dns(SocketAddr, String),
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
}

impl ProbeResult {
    fn success(ms: f64) -> Self {
        Self {
            ok: true,
            latency_ms: Some(ms),
            error: None,
        }
    }
    pub fn fail(err: String) -> Self {
        Self {
            ok: false,
            latency_ms: None,
            error: Some(err),
        }
    }
}

/// Raw ICMP sockets need CAP_NET_RAW on Linux; fall back to unprivileged
/// DGRAM ICMP (works on macOS, and on Linux when ping_group_range allows).
pub fn make_ping_client() -> anyhow::Result<Client> {
    let raw = PingConfig::builder().kind(ICMP::V4).build();
    match Client::new(&raw) {
        Ok(c) => Ok(c),
        Err(raw_err) => {
            let dgram = PingConfig::builder()
                .kind(ICMP::V4)
                .sock_type_hint(socket2::Type::DGRAM)
                .build();
            Client::new(&dgram).map_err(|dgram_err| {
                anyhow::anyhow!(
                    "cannot create ICMP socket (raw: {raw_err}; dgram: {dgram_err}). \
                     On Linux grant CAP_NET_RAW - the provided systemd unit does this, \
                     or run: sudo setcap cap_net_raw+ep /path/to/pi-watcher"
                )
            })
        }
    }
}

pub async fn run_probe(
    spec: &ProbeSpec,
    ping_client: Option<&Client>,
    ident: u16,
    seq: u16,
    timeout: Duration,
) -> ProbeResult {
    let outcome = match spec {
        ProbeSpec::Ping(ip) => {
            let Some(client) = ping_client else {
                return ProbeResult::fail("no ping client".into());
            };
            ping(client, *ip, ident, seq, timeout).await
        }
        ProbeSpec::Dns(server, name) => dns_query(*server, name, timeout).await,
    };
    match outcome {
        Ok(ms) => ProbeResult::success(ms),
        Err(e) => ProbeResult::fail(e),
    }
}

async fn ping(
    client: &Client,
    ip: IpAddr,
    ident: u16,
    seq: u16,
    timeout: Duration,
) -> Result<f64, String> {
    let payload = [0u8; 16];
    let mut pinger = client.pinger(ip, PingIdentifier(ident)).await;
    pinger.timeout(timeout);
    match pinger.ping(PingSequence(seq), &payload).await {
        Ok((_packet, rtt)) => Ok(rtt.as_secs_f64() * 1000.0),
        Err(e) => Err(e.to_string()),
    }
}

/// Minimal hand-rolled DNS query: we only need "did this server answer an
/// A lookup, and how fast", so a full resolver dependency isn't warranted.
async fn dns_query(server: SocketAddr, name: &str, timeout: Duration) -> Result<f64, String> {
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| format!("bind: {e}"))?;

    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xffff) as u16;

    let mut msg = Vec::with_capacity(32 + name.len());
    msg.extend_from_slice(&id.to_be_bytes());
    // flags: RD; QDCOUNT=1, everything else 0
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("bad query name '{name}'"));
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

    let start = Instant::now();
    sock.send_to(&msg, server)
        .await
        .map_err(|e| format!("send: {e}"))?;

    // Ignore stray datagrams (wrong source or transaction id) until the
    // deadline instead of failing on the first one.
    let deadline = start + timeout;
    let mut buf = [0u8; 512];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timeout".into());
        }
        let (n, from) = match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
            Err(_) => return Err("timeout".into()),
            Ok(Err(e)) => return Err(format!("recv: {e}")),
            Ok(Ok(v)) => v,
        };
        if from.ip() != server.ip() || n < 12 || buf[0..2] != id.to_be_bytes() {
            continue;
        }
        if buf[2] & 0x80 == 0 {
            // QR=0: something echoed our query back. Keep waiting for the
            // real answer like any other stray datagram.
            continue;
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        let rcode = buf[3] & 0x0f;
        if rcode != 0 {
            return Err(format!("dns rcode {rcode}"));
        }
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        if ancount == 0 {
            return Err("no answers".into());
        }
        return Ok(ms);
    }
}
