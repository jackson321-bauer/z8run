//! Verbindungsaufbau: SQLCipher-Key-Hülle + WAL + vec-Registrierung.

use crate::dbnode::crypto::KeyEnvelope;
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::vec;
use crate::dbnode::wal;
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

/// Öffnet eine SQLCipher-Verbindung mit Key-Hülle (vec ist registriert).
pub fn open_encrypted(path: &Path, key: &KeyEnvelope) -> DbResult<Connection> {
    vec::register_auto_extension();
    let conn = Connection::open(path)?;
    let hex = hex::encode(key.as_bytes());
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
    conn.busy_timeout(Duration::from_secs(30))?;
    // Erster DB-Zugriff entscheidet über den Key (sonst "file is not a database").
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))?;
    Ok(conn)
}

/// `ram_budget` steuert den SQLite-Page-Cache dieser DB (echtes per-DB-
/// Budget, kein totes Config-Feld). Negativer cache_size = KiB.
pub fn prepare_writer(conn: &Connection, ram_budget: usize) -> DbResult<()> {
    let cache_kb = (ram_budget / 1024).max(256) as i64;
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA cache_size=-{cache_kb};"
    ))?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(DbError::new(
            "SQLITE",
            format!("journal_mode={mode}, erwartet wal"),
        ));
    }
    wal::ensure_epoch_table(conn)?;
    ensure_blob_tables(conn)
}

/// Blob-Meta-/Session-Tabellen: Schema wie die Epochen-Tabelle direkt beim
/// Öffnen (kein WAL-Verbrauch); Zeilen selbst laufen über den WAL-Schreibpfad.
pub fn ensure_blob_tables(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS linefs_blobs (\
           blob_id TEXT PRIMARY KEY, name TEXT NOT NULL, mime TEXT NOT NULL,\
           groesse INTEGER NOT NULL, sha256_klartext TEXT NOT NULL,\
           content_key_huellereferenz TEXT NOT NULL, storage_uri TEXT NOT NULL,\
           epoch INTEGER NOT NULL, owner TEXT NOT NULL, parts INTEGER NOT NULL,\
           session_id TEXT, chunk_index INTEGER, dauer_ms INTEGER,\
           created_at TEXT NOT NULL);\
         CREATE TABLE IF NOT EXISTS linefs_blob_sessions (\
           session_id TEXT PRIMARY KEY, owner TEXT NOT NULL, mime TEXT NOT NULL,\
           chunk_ids TEXT NOT NULL, gesamt_sha256 TEXT NOT NULL,\
           dauer_ms INTEGER NOT NULL, session_key_huellereferenz TEXT NOT NULL,\
           epoch INTEGER NOT NULL, created_at TEXT NOT NULL);",
    )?;
    Ok(())
}

/// Frische Readonly-Verbindung: paralleles Lesen ohne Reservierung.
pub fn open_readonly(path: &Path, key: &KeyEnvelope) -> DbResult<Connection> {
    vec::register_auto_extension();
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let hex = hex::encode(key.as_bytes());
    conn.execute_batch(&format!(
        "PRAGMA key = \"x'{hex}'\"; PRAGMA query_only=ON;"
    ))?;
    conn.busy_timeout(Duration::from_secs(30))?;
    Ok(conn)
}
