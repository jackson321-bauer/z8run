//! WAL-Strom (Geschriebene Dateien), Zeilen-Epochen, DECKEL-Regel und
//! lokaler Zustand. Der WAL ist der einzige Schreibstrom (nie die DB).

use crate::dbnode::types::{DbError, DbResult};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const WAL_MAX_LINES: usize = 205;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalObject {
    pub nr: u64,
    pub prev_hash: String,
    pub db: String,
    pub seal: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalInner {
    pub sql: String,
    pub params: Vec<Value>,
    pub ts: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalState {
    pub next_nr: u64,
    pub last_wal: u64,
    pub synced: u64,
    pub prev_hash: String,
    pub snap_nr: u64,
}

pub fn wal_key(db: &str, nr: u64) -> String {
    format!("wal/{db}/{nr:08}.json")
}
pub fn snap_key(db: &str, nr: u64) -> String {
    format!("snap/{db}/{nr:08}.db")
}
pub fn snap_meta_key(db: &str, nr: u64) -> String {
    format!("snap/{db}/{nr:08}.json")
}

pub fn nr_aus_key(key: &str) -> Option<u64> {
    let file = key.rsplit('/').next()?;
    let stem = file.split('.').next()?;
    stem.parse::<u64>().ok()
}

/// DECKEL-Regel: kaputtes/zu großes SQL wird am Commit abgelehnt.
pub fn validate_sql(sql: &str) -> DbResult<()> {
    if sql.contains('\0') {
        return Err(DbError::new("DECKEL", "SQL enthält Null-Byte"));
    }
    if sql.lines().count() > WAL_MAX_LINES {
        return Err(DbError::new(
            "DECKEL",
            format!("SQL überschreitet {WAL_MAX_LINES} Zeilen"),
        ));
    }
    Ok(())
}

pub fn json_to_sql(v: &Value) -> SqlValue {
    match v {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Integer(*b as i64),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlValue::Integer(i)
            } else {
                SqlValue::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => SqlValue::Text(s.clone()),
        other => SqlValue::Text(other.to_string()),
    }
}

fn value_ref_to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => Value::from(f),
        ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).to_string()),
        ValueRef::Blob(b) => Value::from(base64_encode(b)),
    }
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Führt ein Statement aus; liefert (affected, columns, rows).
pub fn exec_sql(
    conn: &Connection,
    sql: &str,
    params: &[Value],
) -> DbResult<(u64, Vec<String>, Vec<Vec<Value>>)> {
    let mut stmt = conn.prepare(sql)?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    if cols.is_empty() {
        let affected = stmt.execute(params_from_iter(params.iter().map(json_to_sql)))?;
        return Ok((affected as u64, Vec::new(), Vec::new()));
    }
    let mut rows_out = Vec::new();
    let mut rows = stmt.query(params_from_iter(params.iter().map(json_to_sql)))?;
    while let Some(row) = rows.next()? {
        let mut vals = Vec::with_capacity(cols.len());
        for i in 0..cols.len() {
            vals.push(value_ref_to_json(row.get_ref(i)?));
        }
        rows_out.push(vals);
    }
    Ok((0, cols, rows_out))
}

/// Zeilen-Epoche lückenlos: genau eine Zeile je WAL-Nummer.
pub fn ensure_epoch_table(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _z8_line_epochs (\
           nr INTEGER PRIMARY KEY, wal_hash TEXT NOT NULL, ts TEXT NOT NULL);",
    )?;
    Ok(())
}

pub fn record_epoch(conn: &Connection, nr: u64, hash: &str) -> DbResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO _z8_line_epochs (nr, wal_hash, ts) VALUES (?1, ?2, ?3)",
        rusqlite::params![nr as i64, hash, chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

pub fn db_dir(local_dir: &Path, db: &str) -> PathBuf {
    local_dir.join(db)
}

pub fn state_pfad(local_dir: &Path, db: &str) -> PathBuf {
    db_dir(local_dir, db).join("state.json")
}

pub fn persist_state(local_dir: &Path, db: &str, st: &LocalState) -> DbResult<()> {
    let dir = db_dir(local_dir, db);
    std::fs::create_dir_all(&dir)
        .map_err(|e| DbError::new("FS", format!("mkdir state: {e}")))?;
    let p = state_pfad(local_dir, db);
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(st)?)
        .map_err(|e| DbError::new("FS", format!("state write: {e}")))?;
    std::fs::rename(&tmp, &p).map_err(|e| DbError::new("FS", format!("state rename: {e}")))?;
    Ok(())
}

pub fn load_state(local_dir: &Path, db: &str) -> Option<LocalState> {
    let data = std::fs::read(state_pfad(local_dir, db)).ok()?;
    serde_json::from_slice(&data).ok()
}

pub fn write_local_wal(local_dir: &Path, db: &str, nr: u64, bytes: &[u8]) -> DbResult<()> {
    let dir = db_dir(local_dir, db).join("wal");
    std::fs::create_dir_all(&dir).map_err(|e| DbError::new("FS", format!("mkdir wal: {e}")))?;
    std::fs::write(dir.join(format!("{nr:08}.json")), bytes)
        .map_err(|e| DbError::new("FS", format!("wal write: {e}")))
}

pub fn read_local_wal(local_dir: &Path, db: &str, nr: u64) -> Option<Vec<u8>> {
    std::fs::read(db_dir(local_dir, db).join("wal").join(format!("{nr:08}.json"))).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deckel_blockiert_nullbyte_und_206_zeilen() {
        assert_eq!(validate_sql("SELECT 1\0").unwrap_err().code, "DECKEL");
        let lang = "SELECT 1;\n".repeat(206);
        assert_eq!(validate_sql(&lang).unwrap_err().code, "DECKEL");
        assert!(validate_sql(&"SELECT 1;\n".repeat(205)).is_ok());
    }

    #[test]
    fn epochen_sind_lueckenlos() {
        let c = Connection::open_in_memory().unwrap();
        ensure_epoch_table(&c).unwrap();
        for nr in 1..=64 {
            record_epoch(&c, nr, "h").unwrap();
        }
        let n: i64 = c
            .query_row("SELECT count(*) FROM _z8_line_epochs", [], |r| r.get(0))
            .unwrap();
        let max: i64 = c
            .query_row("SELECT max(nr) FROM _z8_line_epochs", [], |r| r.get(0))
            .unwrap();
        assert_eq!((n, max), (64, 64));
    }
}
