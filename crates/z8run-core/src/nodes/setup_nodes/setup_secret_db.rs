//! secret.db: SQLCipher-Chiffre über die BESTEHENDE Conn-Schicht
//! (`dbnode::conn::{open_encrypted,open_readonly}`) — kein neuer Transport.
//!
//! Schema: aktive Werte + append-only WORM-Historie (Audit-Spur). Werte
//! werden nie geloggt, nur ihre SHA-256. Harte Löschung ist per Trigger
//! gesperrt; ein Neuanfang geht nur über Cluster-Neuanlage.

use rusqlite::Connection;
use std::path::Path;

use crate::dbnode::conn::{open_encrypted, open_readonly};
use crate::dbnode::crypto::KeyEnvelope;

use super::setup_crypto as sc;

pub const SECRET_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS secrets (
  ns TEXT NOT NULL,
  name TEXT NOT NULL,
  wert TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  version INTEGER NOT NULL,
  aktiv INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (ns, name)
);
CREATE TABLE IF NOT EXISTS secret_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ns TEXT NOT NULL,
  name TEXT NOT NULL,
  op TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  version INTEGER NOT NULL,
  ts TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS secret_history_no_update
  BEFORE UPDATE ON secret_history BEGIN SELECT RAISE(ABORT,'WORM'); END;
CREATE TRIGGER IF NOT EXISTS secret_history_no_delete
  BEFORE DELETE ON secret_history BEGIN SELECT RAISE(ABORT,'WORM'); END;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

fn huelle(db_key_hex: &str) -> Result<KeyEnvelope, String> {
    let raw = hex::decode(db_key_hex).map_err(|e| format!("secret.db key hex: {e}"))?;
    if raw.len() != 32 {
        return Err("secret.db key muss 32 Bytes (64 Hex) haben".into());
    }
    KeyEnvelope::derive(&raw, "z8-secret-db").map_err(|e| format!("secret.db key: {e}"))
}

fn journal(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )
    .map_err(|e| format!("secret.db pragmas: {e}"))
}

/// Legt eine neue secret.db an und liefert die fertigen Datei-Bytes.
pub fn erzeuge(
    path: &Path,
    db_key_hex: &str,
    space: &str,
    user: &str,
) -> Result<Vec<u8>, String> {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let key = huelle(db_key_hex)?;
    let conn = open_encrypted(path, &key).map_err(|e| format!("secret.db open: {e}"))?;
    journal(&conn)?;
    conn.execute_batch(SECRET_SCHEMA)
        .map_err(|e| format!("secret.db schema: {e}"))?;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES ('format','z8-secret-db/1')",
        [],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES ('space',?1)",
        [space],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES ('user',?1)",
        [user],
    )
    .map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| format!("secret.db checkpoint: {e}"))?;
    drop(conn);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    std::fs::read(path).map_err(|e| format!("secret.db read: {e}"))
}

/// Öffnet die secret.db LESEND (dieselbe `open_readonly`-Naht wie der Proxy).
pub fn oeffne_readonly(path: &Path, db_key_hex: &str) -> Result<Connection, String> {
    let key = huelle(db_key_hex)?;
    open_readonly(path, &key).map_err(|e| format!("secret.db readonly: {e}"))
}

/// Liest den aktiven Secret-Snapshot (ns, name, wert) READ-ONLY.
/// Wird vom Proxy benutzt (Conn-Naht + Label "z8-secret-db", keine Kopie).
pub fn lies_aktive(path: &Path, db_key_hex: &str) -> Result<Vec<(String, String, String)>, String> {
    let conn = oeffne_readonly(path, db_key_hex)?;
    let mut stmt = conn
        .prepare("SELECT ns,name,wert FROM secrets WHERE aktiv=1 ORDER BY ns,name")
        .map_err(|e| format!("secret.db snapshot: {e}"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| format!("secret.db snapshot: {e}"))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("secret.db snapshot: {e}"))?);
    }
    Ok(out)
}

/// Öffnet die secret.db SCHREIBEND für die Setup-API.
pub fn oeffne_rw(path: &Path, db_key_hex: &str) -> Result<Connection, String> {
    let key = huelle(db_key_hex)?;
    let conn = open_encrypted(path, &key).map_err(|e| format!("secret.db open: {e}"))?;
    journal(&conn)?;
    Ok(conn)
}

fn historie(conn: &Connection, ns: &str, name: &str, op: &str, sha: &str, v: i64) -> Result<(), String> {
    conn.execute(
        "INSERT INTO secret_history (ns,name,op,sha256,version,ts) VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![ns, name, op, sha, v, chrono::Utc::now().to_rfc3339()],
    )
    .map_err(|e| format!("secret.db historie: {e}"))?;
    Ok(())
}

pub fn setzen(conn: &Connection, ns: &str, name: &str, wert: &str) -> Result<(String, i64), String> {
    let sha = sc::sha_hex(wert.as_bytes());
    let ts = chrono::Utc::now().to_rfc3339();
    let alt: Option<i64> = conn
        .query_row(
            "SELECT version FROM secrets WHERE ns=?1 AND name=?2",
            rusqlite::params![ns, name],
            |r| r.get(0),
        )
        .ok();
    let v = alt.map(|x| x + 1).unwrap_or(1);
    conn.execute(
        "INSERT INTO secrets (ns,name,wert,sha256,version,aktiv,updated_at)
         VALUES (?1,?2,?3,?4,?5,1,?6)
         ON CONFLICT(ns,name) DO UPDATE SET
           wert=excluded.wert, sha256=excluded.sha256,
           version=excluded.version, aktiv=1, updated_at=excluded.updated_at",
        rusqlite::params![ns, name, wert, sha, v, ts],
    )
    .map_err(|e| format!("secret.db setzen: {e}"))?;
    historie(conn, ns, name, "setzen", &sha, v)?;
    Ok((sha, v))
}

pub fn rotieren(conn: &Connection, ns: &str, name: &str, wert: &str) -> Result<(String, i64), String> {
    let sha = sc::sha_hex(wert.as_bytes());
    let ts = chrono::Utc::now().to_rfc3339();
    let alt: i64 = conn
        .query_row(
            "SELECT version FROM secrets WHERE ns=?1 AND name=?2",
            rusqlite::params![ns, name],
            |r| r.get(0),
        )
        .map_err(|_| format!("secret-rotieren: {ns}/{name} existiert nicht"))?;
    let v = alt + 1;
    conn.execute(
        "UPDATE secrets SET wert=?3, sha256=?4, version=?5, aktiv=1, updated_at=?6
         WHERE ns=?1 AND name=?2",
        rusqlite::params![ns, name, wert, sha, v, ts],
    )
    .map_err(|e| format!("secret.db rotieren: {e}"))?;
    historie(conn, ns, name, "rotieren", &sha, v)?;
    Ok((sha, v))
}

pub fn revozieren(conn: &Connection, ns: &str, name: &str) -> Result<(String, i64), String> {
    let ts = chrono::Utc::now().to_rfc3339();
    let (sha, alt): (String, i64) = conn
        .query_row(
            "SELECT sha256, version FROM secrets WHERE ns=?1 AND name=?2",
            rusqlite::params![ns, name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| format!("secret-revozieren: {ns}/{name} existiert nicht"))?;
    let v = alt + 1;
    conn.execute(
        "UPDATE secrets SET aktiv=0, version=?3, updated_at=?4 WHERE ns=?1 AND name=?2",
        rusqlite::params![ns, name, v, ts],
    )
    .map_err(|e| format!("secret.db revozieren: {e}"))?;
    historie(conn, ns, name, "revozieren", &sha, v)?;
    Ok((sha, v))
}

/// Nur Namen/Hashes/Metadaten — NIEMALS Werte.
pub fn liste(conn: &Connection) -> Result<Vec<serde_json::Value>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ns,name,sha256,version,aktiv,updated_at FROM secrets ORDER BY ns,name",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "ns": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "sha256": r.get::<_, String>(2)?,
                "version": r.get::<_, i64>(3)?,
                "aktiv": r.get::<_, i64>(4)? == 1,
                "updated_at": r.get::<_, String>(5)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

pub fn checkpoint(conn: &Connection) -> Result<(), String> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| format!("secret.db checkpoint: {e}"))
}
