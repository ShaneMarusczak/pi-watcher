use anyhow::Context;
use rusqlite::{params, params_from_iter, types::Value, Connection};

pub struct Store {
    conn: Connection,
}

pub struct HistoryRow {
    pub target: String,
    pub bucket: u64,
    pub avg_ms: Option<f64>,
    pub total: u32,
    pub fails: u32,
}

pub struct EventRow {
    pub ts: u64,
    pub layer: String,
    pub kind: String,
    pub message: String,
    pub duration_secs: Option<u64>,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Store> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path).with_context(|| format!("opening database {path}"))?;
        // WAL + synchronous=NORMAL keeps SD-card writes cheap and safe enough.
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA journal_size_limit = 8388608;
            PRAGMA busy_timeout = 5000;
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                target TEXT NOT NULL,
                ok INTEGER NOT NULL,
                latency_ms REAL
            );
            CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
            CREATE INDEX IF NOT EXISTS idx_samples_target_ts ON samples(target, ts);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                layer TEXT NOT NULL,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                duration_secs INTEGER,
                notified INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            "#,
        )
        .context("initializing schema")?;
        Ok(Store { conn })
    }

    /// All samples in one cycle share the same timestamp so per-cycle
    /// aggregation (GROUP BY ts) works.
    pub fn insert_cycle(
        &mut self,
        ts: u64,
        rows: &[(String, bool, Option<f64>)],
    ) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO samples (ts, target, ok, latency_ms) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (name, ok, ms) in rows {
                stmt.execute(params![ts as i64, name, *ok as i64, ms])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert_event(
        &mut self,
        ts: u64,
        layer: &str,
        kind: &str,
        message: &str,
        duration_secs: Option<u64>,
        notified: bool,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO events (ts, layer, kind, message, duration_secs, notified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ts as i64,
                layer,
                kind,
                message,
                duration_secs.map(|d| d as i64),
                notified as i64
            ],
        )?;
        Ok(())
    }

    pub fn history(&self, from: u64, bucket: u64) -> anyhow::Result<Vec<HistoryRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT target, (ts / ?1) * ?1 AS b, AVG(latency_ms), COUNT(*),
                    SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END)
             FROM samples WHERE ts >= ?2
             GROUP BY target, b ORDER BY b ASC",
        )?;
        let rows = stmt
            .query_map(params![bucket as i64, from as i64], |r| {
                Ok(HistoryRow {
                    target: r.get(0)?,
                    bucket: r.get::<_, i64>(1)? as u64,
                    avg_ms: r.get(2)?,
                    total: r.get::<_, i64>(3)? as u32,
                    fails: r.get::<_, i64>(4)? as u32,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn events(&self, limit: u32) -> anyhow::Result<Vec<EventRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, layer, kind, message, duration_secs
             FROM events ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(EventRow {
                    ts: r.get::<_, i64>(0)? as u64,
                    layer: r.get(1)?,
                    kind: r.get(2)?,
                    message: r.get(3)?,
                    duration_secs: r.get::<_, Option<i64>>(4)?.map(|d| d as u64),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Fraction (0..=1) of cycles in which at least one of `targets` answered.
    pub fn uptime(&self, from: u64, targets: &[String]) -> anyhow::Result<Option<f64>> {
        if targets.is_empty() {
            return Ok(None);
        }
        let placeholders = vec!["?"; targets.len()].join(",");
        let sql = format!(
            "SELECT AVG(u) FROM (
                SELECT MAX(ok) AS u FROM samples
                WHERE ts >= ? AND target IN ({placeholders})
                GROUP BY ts
             )"
        );
        let mut args: Vec<Value> = vec![Value::Integer(from as i64)];
        args.extend(targets.iter().map(|t| Value::Text(t.clone())));
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let v: Option<f64> = stmt.query_row(params_from_iter(args), |r| r.get(0))?;
        Ok(v)
    }

    /// (outage count, total downtime seconds) for the internet layer since `from`.
    pub fn outage_stats(&self, from: u64) -> anyhow::Result<(u32, u64)> {
        let outages: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE layer = 'internet' AND kind = 'down' AND ts >= ?1",
            params![from as i64],
            |r| r.get(0),
        )?;
        let downtime: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(duration_secs), 0) FROM events
             WHERE layer = 'internet' AND kind = 'up' AND ts >= ?1",
            params![from as i64],
            |r| r.get(0),
        )?;
        Ok((outages as u32, downtime as u64))
    }

    pub fn prune_samples(&mut self, before: u64) -> anyhow::Result<usize> {
        let n = self
            .conn
            .execute("DELETE FROM samples WHERE ts < ?1", params![before as i64])?;
        Ok(n)
    }
}
