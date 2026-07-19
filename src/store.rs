use anyhow::Context;
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};

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

/// Last observed state of one target, for rehydration after a restart.
pub struct TargetResume {
    pub up: bool,
    /// Start of the trailing failure streak (None if it never succeeded).
    pub down_since: Option<u64>,
    /// Whether the down event for this streak was notified (host targets).
    pub notified: bool,
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
                target TEXT,
                message TEXT NOT NULL,
                duration_secs INTEGER,
                notified INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            "#,
        )
        .context("initializing schema")?;
        // Databases created before the target column existed: add it in place.
        let has_target: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'target'",
            [],
            |r| r.get(0),
        )?;
        if has_target == 0 {
            conn.execute("ALTER TABLE events ADD COLUMN target TEXT", [])
                .context("migrating events table")?;
        }
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

    #[allow(clippy::too_many_arguments)]
    pub fn insert_event(
        &mut self,
        ts: u64,
        layer: &str,
        kind: &str,
        target: Option<&str>,
        message: &str,
        duration_secs: Option<u64>,
        notified: bool,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO events (ts, layer, kind, target, message, duration_secs, notified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ts as i64,
                layer,
                kind,
                target,
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
    ///
    /// Window-edge semantics are approximate by design: outages are counted by
    /// their "down" event's timestamp, downtime by the "up" event's recorded
    /// duration. An outage still in progress counts as an outage with no
    /// downtime yet; one that started before the window but recovered inside
    /// it contributes its full duration.
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

    /// Timestamp of the most recent probe cycle, if any.
    pub fn latest_cycle_ts(&self) -> anyhow::Result<Option<u64>> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT MAX(ts) FROM samples", [], |r| r.get(0))?;
        Ok(v.map(|t| t as u64))
    }

    /// Last observed state of `name` from its samples, plus (for host targets)
    /// whether the current down streak was notified, from its last event.
    pub fn target_resume(&self, name: &str) -> anyhow::Result<Option<TargetResume>> {
        let last_ok: Option<i64> = self
            .conn
            .query_row(
                "SELECT ok FROM samples WHERE target = ?1 ORDER BY ts DESC, id DESC LIMIT 1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        let Some(last_ok) = last_ok else {
            return Ok(None); // never sampled
        };
        if last_ok != 0 {
            return Ok(Some(TargetResume {
                up: true,
                down_since: None,
                notified: false,
            }));
        }
        let down_since: Option<i64> = self.conn.query_row(
            "SELECT MIN(ts) FROM samples WHERE target = ?1
               AND ts > COALESCE((SELECT MAX(ts) FROM samples WHERE target = ?1 AND ok = 1), 0)",
            params![name],
            |r| r.get(0),
        )?;
        let notified: bool = self
            .conn
            .query_row(
                "SELECT kind, notified FROM events
                 WHERE layer = 'host' AND target = ?1
                 ORDER BY ts DESC, id DESC LIMIT 1",
                params![name],
                |r| {
                    let kind: String = r.get(0)?;
                    let notified: i64 = r.get(1)?;
                    Ok(matches!(kind.as_str(), "down" | "still_down") && notified != 0)
                },
            )
            .optional()?
            .unwrap_or(false);
        Ok(Some(TargetResume {
            up: false,
            down_since: down_since.map(|t| t as u64),
            notified,
        }))
    }

    /// If `layer`'s last recorded state was an unrecovered outage, returns
    /// (outage start ts, whether it was notified). None means it was up.
    pub fn layer_resume(&self, layer: &str) -> anyhow::Result<Option<(u64, bool)>> {
        let last: Option<(String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT kind, ts, notified FROM events
                 WHERE layer = ?1 AND kind IN ('down', 'still_down', 'up')
                 ORDER BY ts DESC, id DESC LIMIT 1",
                params![layer],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((kind, ts, notified)) = last else {
            return Ok(None);
        };
        if kind == "up" {
            return Ok(None);
        }
        // A still_down belongs to an outage that began at the last 'down'.
        let since: i64 = if kind == "down" {
            ts
        } else {
            self.conn
                .query_row(
                    "SELECT ts FROM events WHERE layer = ?1 AND kind = 'down'
                     ORDER BY ts DESC, id DESC LIMIT 1",
                    params![layer],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(ts)
        };
        Ok(Some((since as u64, notified != 0)))
    }

    pub fn prune_samples(&mut self, before: u64) -> anyhow::Result<usize> {
        let n = self
            .conn
            .execute("DELETE FROM samples WHERE ts < ?1", params![before as i64])?;
        Ok(n)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mem() -> Store {
        Store::open(":memory:").unwrap()
    }

    fn row(name: &str, ok: bool, ms: Option<f64>) -> (String, bool, Option<f64>) {
        (name.to_string(), ok, ms)
    }

    #[test]
    fn uptime_counts_cycles_where_any_target_answered() {
        let mut s = mem();
        s.insert_cycle(100, &[row("a", true, Some(10.0)), row("b", false, None)])
            .unwrap();
        s.insert_cycle(200, &[row("a", false, None), row("b", false, None)])
            .unwrap();
        let names = vec!["a".to_string(), "b".to_string()];
        assert_eq!(s.uptime(0, &names).unwrap(), Some(0.5));
        assert_eq!(s.uptime(150, &names).unwrap(), Some(0.0));
        assert_eq!(s.uptime(0, &[]).unwrap(), None);
    }

    #[test]
    fn outage_stats_counts_downs_and_sums_up_durations() {
        let mut s = mem();
        s.insert_event(100, "internet", "down", None, "down", None, true)
            .unwrap();
        s.insert_event(400, "internet", "up", None, "up", Some(300), true)
            .unwrap();
        // still_down must not inflate the outage count.
        s.insert_event(500, "internet", "still_down", None, "still", None, true)
            .unwrap();
        assert_eq!(s.outage_stats(0).unwrap(), (1, 300));
        assert_eq!(s.outage_stats(200).unwrap(), (0, 300));
    }

    #[test]
    fn target_resume_finds_trailing_failure_streak() {
        let mut s = mem();
        s.insert_cycle(100, &[row("nas", true, Some(5.0))]).unwrap();
        s.insert_cycle(200, &[row("nas", false, None)]).unwrap();
        s.insert_cycle(300, &[row("nas", false, None)]).unwrap();
        s.insert_event(300, "host", "down", Some("nas"), "nas down", None, true)
            .unwrap();

        let r = s.target_resume("nas").unwrap().unwrap();
        assert!(!r.up);
        assert_eq!(r.down_since, Some(200));
        assert!(r.notified);

        assert!(s.target_resume("unknown").unwrap().is_none());

        s.insert_cycle(400, &[row("nas", true, Some(5.0))]).unwrap();
        let r = s.target_resume("nas").unwrap().unwrap();
        assert!(r.up);
    }

    #[test]
    fn layer_resume_reports_unrecovered_outage_from_its_start() {
        let mut s = mem();
        assert!(s.layer_resume("internet").unwrap().is_none());

        s.insert_event(100, "internet", "down", None, "down", None, false)
            .unwrap();
        assert_eq!(s.layer_resume("internet").unwrap(), Some((100, false)));

        // still_down points back at the original down for the start time.
        s.insert_event(200, "internet", "still_down", None, "still", None, true)
            .unwrap();
        assert_eq!(s.layer_resume("internet").unwrap(), Some((100, true)));

        s.insert_event(300, "internet", "up", None, "up", Some(200), true)
            .unwrap();
        assert!(s.layer_resume("internet").unwrap().is_none());
    }

    #[test]
    fn latest_cycle_ts_tracks_samples() {
        let mut s = mem();
        assert_eq!(s.latest_cycle_ts().unwrap(), None);
        s.insert_cycle(123, &[row("a", true, Some(1.0))]).unwrap();
        assert_eq!(s.latest_cycle_ts().unwrap(), Some(123));
    }

    #[test]
    fn migrates_events_table_without_target_column() {
        let dir = std::env::temp_dir().join(format!("pi-watcher-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("migrate.db");
        let path_str = path.to_str().unwrap();
        {
            let conn = Connection::open(path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    ts INTEGER NOT NULL,
                    layer TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    duration_secs INTEGER,
                    notified INTEGER NOT NULL DEFAULT 1
                );
                INSERT INTO events (ts, layer, kind, message) VALUES (1, 'internet', 'down', 'x');",
            )
            .unwrap();
        }
        let mut s = Store::open(path_str).unwrap();
        s.insert_event(2, "host", "down", Some("nas"), "y", None, true)
            .unwrap();
        assert_eq!(s.events(10).unwrap().len(), 2);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
