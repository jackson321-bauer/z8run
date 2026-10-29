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

pub fn prepare_writer(conn: &Connection) -> DbResult<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(DbError::new(
            "SQLITE",
            format!("journal_mode={mode}, erwartet wal"),
        ));
    }
    wal::ensure_epoch_table(conn)
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
