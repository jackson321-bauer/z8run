//! Pfad-Sicht der Ordner-Welt: Baum ist Wahrheit, Pfad wird gerendert.
//! Keine Schreiblogik — reine Auflösung/Rendering.

use super::linefs_rows::schema::ORDNER_WURZEL;
use rusqlite::Connection;

pub(crate) const MAX_TIEFE: i64 = 32;
const MAX_NAME: usize = 255;

pub(crate) fn pruefe_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NAME || name == "." || name == ".." {
        return Err(format!("ungueltiger Ordnername: {name:?}"));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(format!("Ordnername darf kein '/'/Null-Byte enthalten: {name:?}"));
    }
    Ok(())
}

pub(crate) fn id_fuer(conn: &Connection, eltern_id: i64, name: &str) -> Option<i64> {
    conn.query_row(
        "SELECT id FROM ordner WHERE eltern_id = ?1 AND name = ?2",
        rusqlite::params![eltern_id, name],
        |r| r.get(0),
    )
    .ok()
}

#[allow(dead_code)]
pub(crate) fn ordner_id_fuer_pfad(conn: &Connection, pfad: &str) -> Result<i64, String> {
    let p = pfad.trim_matches('/');
    if p.is_empty() {
        return Ok(ORDNER_WURZEL);
    }
    let mut cur = ORDNER_WURZEL;
    for teil in p.split('/') {
        pruefe_name(teil)?;
        cur = id_fuer(conn, cur, teil).ok_or_else(|| format!("Ordner nicht gefunden: {pfad}"))?;
    }
    Ok(cur)
}

/// PFAD -> datei_id. Bare Namen werden zuerst in der Wurzel gesucht.
pub(crate) fn datei_id_fuer_pfad(conn: &Connection, pfad: &str) -> Result<i64, String> {
    let p = pfad.trim_matches('/');
    if p.is_empty() {
        return Err("Dateipfad leer".into());
    }
    let teile: Vec<&str> = p.split('/').collect();
    if teile.len() == 1 {
        if let Ok(id) = conn.query_row(
            "SELECT datei_id FROM dateien WHERE ordner_id = 0 AND name = ?1 AND geloescht = 0",
            [p],
            |r| r.get(0),
        ) {
            return Ok(id);
        }
    }
    let mut ordner = ORDNER_WURZEL;
    for teil in &teile[..teile.len() - 1] {
        pruefe_name(teil)?;
        ordner = id_fuer(conn, ordner, teil)
            .ok_or_else(|| format!("Ordner nicht gefunden: {pfad}"))?;
    }
    let name = teile[teile.len() - 1];
    conn.query_row(
        "SELECT datei_id FROM dateien WHERE ordner_id = ?1 AND name = ?2 AND geloescht = 0",
        rusqlite::params![ordner, name],
        |r| r.get(0),
    )
    .map_err(|_| format!("Datei nicht gefunden: {pfad}"))
}

pub(crate) fn pfad_von_ordner(conn: &Connection, id: i64) -> Result<String, String> {
    let mut teile = Vec::new();
    let mut cur = id;
    let mut guard = 0;
    while cur != ORDNER_WURZEL {
        guard += 1;
        if guard > MAX_TIEFE + 1 {
            return Err("Ordner-Zyklus".into());
        }
        let (eltern, name): (i64, String) = conn
            .query_row("SELECT eltern_id, name FROM ordner WHERE id = ?1", [cur], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(|_| format!("Ordner {cur} existiert nicht"))?;
        teile.push(name);
        cur = eltern;
    }
    teile.reverse();
    Ok(teile.join("/"))
}

pub(crate) fn pfad_von_datei(conn: &Connection, datei_id: i64) -> Result<String, String> {
    let (ordner, name): (i64, String) = conn
        .query_row(
            "SELECT ordner_id, name FROM dateien WHERE datei_id = ?1",
            [datei_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| e.to_string())?;
    let basis = pfad_von_ordner(conn, ordner)?;
    Ok(if basis.is_empty() { name } else { format!("{basis}/{name}") })
}
