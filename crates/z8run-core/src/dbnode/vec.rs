//! sqlite-vec v0.1.9 EINGEBRANNT (build.rs kompiliert die C-Quelle).
//!
//! Registrierung NICHT per load_extension, sondern per
//! sqlite3_auto_extension (extra_init-Naht von SQLite). Das Feature
//! `load_extension` ist in Cargo.toml NICHT aktiviert.

use crate::dbnode::types::{DbError, DbResult};
use rusqlite::Connection;
use std::os::raw::{c_char, c_int};
use std::sync::Once;

extern "C" {
    fn sqlite3_vec_init(
        db: *mut rusqlite::ffi::sqlite3,
        pz_err_msg: *mut *mut c_char,
        api: *const rusqlite::ffi::sqlite3_api_routines,
    ) -> c_int;
}

static INIT: Once = Once::new();

/// Registriert vec0 global für alle danach geöffneten Verbindungen.
pub fn register_auto_extension() {
    INIT.call_once(|| unsafe {
        let _ = rusqlite::ffi::sqlite3_auto_extension(Some(sqlite3_vec_init));
    });
}

/// Beweist, dass vec0 ohne aktivierten Loader vorhanden ist.
pub fn verify(conn: &Connection) -> DbResult<String> {
    let v: String = conn
        .query_row("SELECT vec_version()", [], |r| r.get(0))
        .map_err(|e| DbError::new("VEC", format!("vec_version fehlt: {e}")))?;
    if !v.starts_with('v') {
        return Err(DbError::new("VEC", format!("unerwartete vec_version: {v}")));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_ist_ohne_load_extension_verfuegbar() {
        register_auto_extension();
        let c = Connection::open_in_memory().unwrap();
        let v = verify(&c).unwrap();
        assert!(v.starts_with('v'));
        c.execute_batch("CREATE VIRTUAL TABLE t USING vec0(embedding float[4]);")
            .unwrap();
    }

    #[test]
    fn cargo_toml_aktiviert_load_extension_nicht() {
        let toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let rusqlite_line = toml
            .lines()
            .find(|l| l.trim_start().starts_with("rusqlite "))
            .unwrap();
        assert!(!rusqlite_line.contains("load_extension"));
    }
}
