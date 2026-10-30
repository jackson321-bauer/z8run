//! Zeilen-Welt-Schema (Port des CE-Kerns, an z8 angepasst).
//!
//! Adaptionen gemaess bauplan-z8-linefs:
//!   · SEITE_MAX bleibt die PHYSIKALISCHE Seitengroesse (205) — die
//!     205er-POLICY ist Konfig (DbNodeConfig::zeilen_limit, 0 = aus).
//!   · art-Spalte bleibt schema-kompatibel ('code' | 'dokument'),
//!     Policy-Prüfung ist per Default AUS.
//!   · KEIN binaer_s3/binaer_key/Secret.db im z8-Produkt; Binaer laeuft
//!     einheitlich ueber linefs_blobs. Fuer die Matrix-Befehle bleiben
//!     binaer_blob_id/binaer_sha als Verweis-Spalten.
//!   · Ordner-Baum: ordner(id, eltern_id, name), dateien.ordner_id.
//!     Pfade sind gerenderte Sicht, nie gespeicherte Wahrheit.
//!
//! physikalische Seite = s_{datei_id}_{seite}; zeilen_epochen haelt JEDE
//! Version fuer immer (WORM), Hashkette je Geschichtszeile.

#[cfg(not(target_arch = "wasm32"))]
use rusqlite::Connection;

/// Physikalische Zeilen je Seite (Kern-Physik, unveraendert 205).
pub const SEITE_MAX: u32 = 205;
/// Segment-Chunk in Bytes (Zeilenmonster, §3.2).
pub const ZEILEN_LIMIT: usize = 8192;
/// Wurzel-Ordner ist virtuell (id 0), nie als Zeile gespeichert.
pub const ORDNER_WURZEL: i64 = 0;

/// DDL der globalen Tabellen (ohne Seiten-Tabellen s_{d}_{s}).
pub fn ddl_global() -> &'static str {
    "
    CREATE TABLE IF NOT EXISTS dateien (
        datei_id    INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        art         TEXT NOT NULL,                  -- 'code' | 'dokument'
        ordner_id   INTEGER NOT NULL DEFAULT 0,     -- 0 = Wurzel
        status      TEXT NOT NULL DEFAULT 'text',   -- 'text' | 'binaer'
        fassung     INTEGER NOT NULL DEFAULT 0,
        hashkette   TEXT NOT NULL DEFAULT '',
        ts          TEXT NOT NULL DEFAULT '',
        urheber     TEXT NOT NULL DEFAULT '',
        binaer_blob_id TEXT,
        binaer_sha  TEXT,
        geloescht   INTEGER NOT NULL DEFAULT 0,
        UNIQUE (ordner_id, name)
    );
    CREATE TABLE IF NOT EXISTS seiten (
        datei_id    INTEGER NOT NULL,
        seite       INTEGER NOT NULL,
        PRIMARY KEY (datei_id, seite)
    );
    CREATE TABLE IF NOT EXISTS zeilen_epochen (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        datei_id    INTEGER NOT NULL,
        seite       INTEGER NOT NULL,
        schluessel  INTEGER NOT NULL,
        nr          INTEGER NOT NULL,
        seg         INTEGER NOT NULL,
        inhalt      TEXT NOT NULL,
        ende        INTEGER NOT NULL,
        fassung     INTEGER NOT NULL,
        geloescht   INTEGER NOT NULL DEFAULT 0,
        ts          TEXT NOT NULL,
        urheber     TEXT NOT NULL,
        vor_hash    TEXT NOT NULL,
        hash        TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_zeilen_lookup
        ON zeilen_epochen (datei_id, schluessel, fassung);
    CREATE TABLE IF NOT EXISTS ordner (
        id          INTEGER PRIMARY KEY,
        eltern_id   INTEGER NOT NULL DEFAULT 0,
        name        TEXT NOT NULL,
        UNIQUE (eltern_id, name)
    );
    "
}

/// DDL EINER Seiten-Tabelle (PK (schluessel, seg) fuer Segmente).
pub fn ddl_seite(datei_id: u64, seite: u32) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS s_{datei_id}_{seite} (
            schluessel  INTEGER NOT NULL,
            nr          INTEGER NOT NULL,
            seg         INTEGER NOT NULL DEFAULT 1,
            inhalt      TEXT NOT NULL,
            ende        INTEGER NOT NULL DEFAULT 1,
            fassung     INTEGER NOT NULL,
            geloescht   INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (schluessel, seg)
        );"
    )
}

/// Name einer Seiten-Tabelle.
pub fn tabelle_seite(datei_id: u64, seite: u32) -> String {
    format!("s_{datei_id}_{seite}")
}

/// Seitennummer einer logischen Zeilennummer (1-basiert, 205er-Physik).
pub fn seite_von_nr(nr: i64) -> i64 {
    (nr - 1) / SEITE_MAX as i64 + 1
}

/// Legt das globale Schema an (idempotent).
#[cfg(not(target_arch = "wasm32"))]
pub fn initialisiere(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(ddl_global())
        .map_err(|e| format!("Schema: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn physik_ist_fest_und_policy_separat() {
        assert_eq!(SEITE_MAX, 205, "Kern-Physik bleibt 205");
        assert!(ZEILEN_LIMIT >= 4096);
        assert_eq!(seite_von_nr(1), 1);
        assert_eq!(seite_von_nr(205), 1);
        assert_eq!(seite_von_nr(206), 2);
    }

    #[test]
    fn schema_idempotent_und_ordner_da() {
        let conn = Connection::open_in_memory().unwrap();
        initialisiere(&conn).unwrap();
        initialisiere(&conn).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN \
                 ('dateien','seiten','zeilen_epochen','ordner')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 4);
        let t = ddl_seite(7, 2);
        assert!(t.contains("s_7_2"));
        assert_eq!(tabelle_seite(7, 2), "s_7_2");
    }
}
