//! SQLite Exec node: executes one SQL statement against an encrypted SQLite
//! file (SQLCipher).
//!
//! The file is supplied by the S3 DB Fetch node (`dbPath`). The node opens the
//! file on demand, applies `PRAGMA key` from the key file, executes exactly one
//! statement, returns rows or affected rows, and writes an audit record to the
//! encrypted meta database.
//!
//! Config:
//!   - keyFile:     file containing a 32-byte key as 64 hex characters
//!                  (empty = plain SQLite, for tests only)
//!   - metaDb:      audit database (created on first use, encrypted)
//!   - cacheDir:    only files below this directory are accepted
//!   - maxRows:     maximum rows returned (default 1000)
//!   - timeoutSecs: statement timeout (default 30)
//!
//! Input:  { "dbPath": "...", "dbAlias": "...", "req": { "body": { "sql": "...", "params": [...] } } }
//! Output: { "status": 200, "db": "...", "rows": [...], "rowsAffected": n, "columns": [...] }
//! Error:  { "status": 400, "error": "..." }

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::{Column, Connection, Row};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub struct SqliteExecNode {
    name: String,
    key_file: String,
    meta_db: String,
    cache_dir: String,
    max_rows: u64,
    timeout_secs: u64,
}

impl SqliteExecNode {
    fn error_output(&self, msg: &FlowMessage, error: impl Into<String>) -> Vec<FlowMessage> {
        let error = error.into();
        warn!(node = %self.name, error = %error, "SQLite exec failed");
        vec![msg.derive(
            msg.source_node,
            "error",
            json!({ "status": 400, "error": error }),
        )]
    }

    fn body<'a>(&self, payload: &'a Value) -> &'a Value {
        payload
            .get("req")
            .and_then(|r| r.get("body"))
            .unwrap_or(payload)
    }

    async fn audit(
        &self,
        db: &str,
        path: &Path,
        sql: &str,
        status: &str,
        rows: usize,
        duration_ms: u128,
        trace_id: &str,
    ) {
        let meta = PathBuf::from(&self.meta_db);
        if let Some(parent) = meta.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let mut conn = match open_conn(&meta, &self.key_file, None, true).await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Audit database unavailable");
                return;
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&meta, std::fs::Permissions::from_mode(0o600));
        }
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                db TEXT,
                db_path TEXT,
                sql_hash TEXT,
                status TEXT,
                rows INTEGER,
                duration_ms INTEGER,
                trace_id TEXT
            )",
        )
        .execute(&mut conn)
        .await;

        let hash = format!("{:x}", Sha256::digest(sql.as_bytes()));
        let _ = sqlx::query(
            "INSERT INTO audit (ts, db, db_path, sql_hash, status, rows, duration_ms, trace_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(db)
        .bind(path.to_string_lossy().to_string())
        .bind(hash)
        .bind(status)
        .bind(rows as i64)
        .bind(duration_ms as i64)
        .bind(trace_id)
        .execute(&mut conn)
        .await;
        let _ = conn.close().await;
    }
}

/// Opens a SQLite/SQLCipher connection and applies the key before any page is
/// read. A missing or malformed key is an error; it never falls back to
/// plaintext for an encrypted file.
async fn open_conn(
    path: &Path,
    key_file: &str,
    key_override: Option<&str>,
    create: bool,
) -> Result<SqliteConnection, String> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .read_only(false);
    let mut conn = SqliteConnection::connect_with(&opts)
        .await
        .map_err(|e| format!("open database: {e}"))?;

    let key = match key_override {
        Some(k) if !k.trim().is_empty() => Some(k.trim().to_string()),
        Some(_) => return Err("dbKey is empty".to_string()),
        None if !key_file.is_empty() => {
            let raw = std::fs::read_to_string(key_file)
                .map_err(|e| format!("key file {key_file}: {e}"))?;
            Some(raw.trim().to_string())
        }
        None => None,
    };
    if let Some(key) = key {
        if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("key must contain exactly 64 hex characters".to_string());
        }
        sqlx::query(&format!("PRAGMA key = \"x'{key}'\";"))
            .execute(&mut conn)
            .await
            .map_err(|e| format!("apply key: {e}"))?;
        sqlx::query(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;",
        )
        .execute(&mut conn)
        .await
        .map_err(|e| format!("cipher pragmas: {e}"))?;
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM sqlite_master")
            .fetch_one(&mut conn)
            .await
            .map_err(|_| "wrong key or damaged database".to_string())?;
    }

    Ok(conn)
}

fn bind_value<'q>(
    q: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    v: &'q Value,
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    match v {
        Value::Null => q.bind(Option::<String>::None),
        Value::Bool(b) => q.bind(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                q.bind(i)
            } else if let Some(f) = n.as_f64() {
                q.bind(f)
            } else {
                q.bind(n.to_string())
            }
        }
        Value::String(s) => q.bind(s.as_str()),
        other => q.bind(other.to_string()),
    }
}

fn cell_to_json(row: &sqlx::sqlite::SqliteRow, i: usize) -> Value {
    if let Ok(v) = row.try_get::<Option<i64>, _>(i) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(i) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<String>, _>(i) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<Vec<u8>>, _>(i) {
        return v
            .map(|b| json!({ "bytes": b.len() }))
            .unwrap_or(Value::Null);
    }
    Value::Null
}

async fn run_statement(
    conn: &mut SqliteConnection,
    sql: &str,
    params: &[Value],
    max_rows: usize,
) -> Result<(Vec<Value>, Vec<String>, u64, bool), String> {
    let mut q = sqlx::query(sql);
    for p in params {
        q = bind_value(q, p);
    }

    let head = sql
        .trim_start()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();

    if matches!(head.as_str(), "SELECT" | "WITH" | "PRAGMA" | "EXPLAIN") {
        let rows = q.fetch_all(&mut *conn).await.map_err(|e| e.to_string())?;
        let columns: Vec<String> = rows
            .first()
            .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let truncated = rows.len() > max_rows;
        let mut out = Vec::new();
        for row in rows.iter().take(max_rows) {
            let mut obj = serde_json::Map::new();
            for (i, col) in row.columns().iter().enumerate() {
                obj.insert(col.name().to_string(), cell_to_json(row, i));
            }
            out.push(Value::Object(obj));
        }
        Ok((out, columns, 0, truncated))
    } else {
        let result = q.execute(&mut *conn).await.map_err(|e| e.to_string())?;
        Ok((Vec::new(), Vec::new(), result.rows_affected(), false))
    }
}

#[async_trait::async_trait]
impl NodeExecutor for SqliteExecNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        // Pass an upstream error through unchanged. With a single outgoing
        // edge the engine delivers error messages on the same channel; the
        // status switch downstream must see the original status/message.
        if msg
            .payload
            .get("status")
            .and_then(|v| v.as_u64())
            .map(|s| s >= 400)
            .unwrap_or(false)
            && msg.payload.get("error").is_some()
        {
            return Ok(vec![msg.derive(msg.source_node, "error", msg.payload.clone())]);
        }

        let body = self.body(&msg.payload);

        let db_path = match msg
            .payload
            .get("dbPath")
            .and_then(|v| v.as_str())
            .or_else(|| body.get("dbPath").and_then(|v| v.as_str()))
        {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => return Ok(self.error_output(&msg, "Missing 'dbPath' (run S3 DB Fetch first)")),
        };

        let db_alias = msg
            .payload
            .get("dbAlias")
            .and_then(|v| v.as_str())
            .or_else(|| body.get("db").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();

        let key_override = msg
            .payload
            .get("dbKey")
            .and_then(|v| v.as_str())
            .or_else(|| body.get("dbKey").and_then(|v| v.as_str()))
            .map(|s| s.to_string());

        let sql = match body.get("sql").and_then(|v| v.as_str()) {
            Some(v) if !v.trim().is_empty() => v.to_string(),
            _ => return Ok(self.error_output(&msg, "Missing 'sql' in request body")),
        };

        let params: Vec<Value> = match body.get("params") {
            Some(Value::Array(a)) => a.clone(),
            Some(Value::Null) | None => Vec::new(),
            Some(_) => return Ok(self.error_output(&msg, "'params' must be an array")),
        };

        let lower = sql.to_ascii_lowercase();
        if lower.contains("attach ") || lower.contains("vacuum ") {
            return Ok(self.error_output(
                &msg,
                "ATTACH and VACUUM are not allowed through the proxy",
            ));
        }

        let cache = PathBuf::from(&self.cache_dir);
        if let Err(e) = tokio::fs::create_dir_all(&cache).await {
            return Ok(self.error_output(&msg, format!("Cache directory: {e}")));
        }
        let cache_canon = match cache.canonicalize() {
            Ok(p) => p,
            Err(e) => return Ok(self.error_output(&msg, format!("Cache directory: {e}"))),
        };
        let path = PathBuf::from(&db_path);
        let path_canon = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => return Ok(self.error_output(&msg, format!("Database file: {e}"))),
        };
        if !path_canon.starts_with(&cache_canon) {
            return Ok(self.error_output(
                &msg,
                "Database file is outside the configured cache directory",
            ));
        }
        if !path_canon.is_file() {
            return Ok(self.error_output(&msg, "Database path is not a file"));
        }

        let mut conn = match open_conn(
            &path_canon,
            &self.key_file,
            key_override.as_deref(),
            false,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => return Ok(self.error_output(&msg, e)),
        };

        let started = Instant::now();
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let result = tokio::time::timeout(
            timeout,
            run_statement(&mut conn, &sql, &params, self.max_rows as usize),
        )
        .await;
        let duration_ms = started.elapsed().as_millis();

        let (rows, columns, rows_affected, truncated, status) = match result {
            Err(_) => {
                let _ = conn.close().await;
                self.audit(
                    &db_alias,
                    &path_canon,
                    &sql,
                    "timeout",
                    0,
                    duration_ms,
                    &msg.trace_id.to_string(),
                )
                .await;
                return Ok(self.error_output(
                    &msg,
                    format!("Query timeout after {}s", self.timeout_secs.max(1)),
                ));
            }
            Ok(Err(e)) => {
                let _ = conn.close().await;
                self.audit(
                    &db_alias,
                    &path_canon,
                    &sql,
                    "error",
                    0,
                    duration_ms,
                    &msg.trace_id.to_string(),
                )
                .await;
                return Ok(self.error_output(&msg, e));
            }
            Ok(Ok((rows, columns, affected, truncated))) => {
                let status = if affected > 0 { "write" } else { "read" };
                (rows, columns, affected, truncated, status)
            }
        };

        let _ = conn.close().await;
        self.audit(
            &db_alias,
            &path_canon,
            &sql,
            status,
            rows.len(),
            duration_ms,
            &msg.trace_id.to_string(),
        )
        .await;

        info!(
            node = %self.name,
            db = %db_alias,
            rows = rows.len(),
            rows_affected,
            duration_ms,
            "SQLite exec completed"
        );

        let payload = json!({
            "status": 200,
            "db": db_alias,
            "dbPath": path_canon.to_string_lossy(),
            "columns": columns,
            "rows": rows,
            "rowsAffected": rows_affected,
            "truncated": truncated,
            "durationMs": duration_ms,
        });
        Ok(vec![msg.derive(msg.source_node, "output", payload)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "keyFile" => key_file: str,
            "metaDb" => meta_db: str,
            "cacheDir" => cache_dir: str,
            "maxRows" => max_rows: u64,
            "timeoutSecs" => timeout_secs: u64,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.meta_db, "SQLite Exec requires a metaDb")?;
        require_non_empty(&self.cache_dir, "SQLite Exec requires a cacheDir")?;
        if self.max_rows == 0 {
            return Err(Z8Error::Internal(
                "SQLite Exec maxRows must be greater than zero".to_string(),
            ));
        }
        if self.timeout_secs == 0 {
            return Err(Z8Error::Internal(
                "SQLite Exec timeoutSecs must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "sqlite-exec"
    }
}

node_factory!(SqliteExecNodeFactory, SqliteExecNode, "sqlite-exec", {
    name: "SQLite Exec".to_string(),
    key_file: "/etc/z8run/db.key".to_string(),
    meta_db: "/data/z8run/kv/meta.db".to_string(),
    cache_dir: "/data/z8run/kv".to_string(),
    max_rows: 1000,
    timeout_secs: 30
});
