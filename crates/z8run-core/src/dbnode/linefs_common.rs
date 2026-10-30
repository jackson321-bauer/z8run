//! Gemeinsame Helfer der Zeilen-Welt (Lesen/Planen, keine WAL-Schreiblogik).

use super::linefs_rows::{
    als_zeilen, haenge_zusammen, ist_zu_stand, tabelle_seite, DateiKopf, IstZeile, Policy,
    ZeileStand,
};
use super::types::{DbError, DbNodeConfig};
use rusqlite::Connection;
use serde_json::Value;

pub(crate) fn sitzung_key(db: &str, session: &str) -> String {
    format!("{db}\u{0}{session}")
}

pub(crate) fn policy(cfg: &DbNodeConfig) -> Policy {
    Policy {
        limit: cfg.zeilen_limit,
        code_docu: cfg.code_docu_unterscheidung,
    }
}

pub(crate) fn kopf(conn: &Connection, datei_id: i64) -> Result<DateiKopf, String> {
    conn.query_row(
        "SELECT name, art, fassung, hashkette, ordner_id FROM dateien
         WHERE datei_id = ?1 AND geloescht = 0",
        [datei_id],
        |r| {
            Ok(DateiKopf {
                name: r.get(0)?,
                art: r.get(1)?,
                fassung: r.get(2)?,
                hashkette: r.get(3)?,
                ordner_id: r.get(4)?,
            })
        },
    )
    .map_err(|e| format!("Datei {datei_id}: {e}"))
}

pub(crate) fn lese_ist(conn: &Connection, datei_id: i64) -> Result<Vec<IstZeile>, String> {
    let seiten: Vec<i64> = {
        let mut stmt = conn
            .prepare("SELECT seite FROM seiten WHERE datei_id = ?1 ORDER BY seite")
            .map_err(|e| e.to_string())?;
        let z = stmt
            .query_map([datei_id], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        z.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?
    };
    let mut ist = Vec::new();
    for s in &seiten {
        let t = tabelle_seite(datei_id as u64, *s as u32);
        let mut stmt = conn
            .prepare(&format!(
                "SELECT schluessel, nr, seg, inhalt, ende, geloescht FROM {t} ORDER BY nr, seg"
            ))
            .map_err(|e| e.to_string())?;
        let z = stmt
            .query_map([], |r| {
                Ok(IstZeile {
                    schluessel: r.get(0)?,
                    nr: r.get(1)?,
                    inhalt: r.get(3)?,
                    ende: r.get(4)?,
                    geloescht: r.get::<_, i64>(5)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in z {
            ist.push(row.map_err(|e| e.to_string())?);
        }
    }
    Ok(ist)
}

pub(crate) fn lese_stand(
    conn: &Connection,
    datei_id: i64,
) -> Result<(DateiKopf, Vec<ZeileStand>), String> {
    let kopf = kopf(conn, datei_id)?;
    let ist = lese_ist(conn, datei_id)?;
    Ok((kopf, ist_zu_stand(&ist)))
}

pub(crate) fn rendere(conn: &Connection, datei_id: i64) -> Result<String, String> {
    let (_, stand) = lese_stand(conn, datei_id)?;
    Ok(haenge_zusammen(&als_zeilen(&stand)))
}

/// Eine Editor-Zeile darf KEINEN Umbruch und KEIN Null-Byte enthalten.
pub(crate) fn pruefe_einzelzeile(inhalt: &str) -> Result<(), String> {
    if inhalt.contains('\n') || inhalt.contains('\r') {
        return Err("DECKEL: Zeileninhalt enthaelt einen Zeilenumbruch — Zeilen sind die Einheit".into());
    }
    if inhalt.as_bytes().contains(&0u8) {
        return Err("DECKEL: Zeileninhalt enthaelt ein Null-Byte (binaer) — Binaerpfad nutzen".into());
    }
    Ok(())
}

/// Index im Sitzungs-Vektor zu einer sichtbaren Zeilennummer (1..n).
pub(crate) fn index_fuer_nr(zeilen: &[ZeileStand], nr: i64) -> Result<usize, String> {
    if nr < 1 {
        return Err(format!("Zeile {nr} existiert nicht (1-basiert)"));
    }
    let mut sichtbar = 0i64;
    for (i, z) in zeilen.iter().enumerate() {
        if z.geloescht {
            continue;
        }
        sichtbar += 1;
        if sichtbar == nr {
            return Ok(i);
        }
    }
    Err(format!("Zeile {nr} existiert nicht"))
}

pub(crate) fn zeilen_json(zeilen: &[ZeileStand]) -> Value {
    let mut out = Vec::new();
    let mut nr = 0i64;
    for z in zeilen.iter().filter(|z| !z.geloescht) {
        nr += 1;
        out.push(serde_json::json!({
            "nr": nr,
            "schluessel": z.schluessel,
            "inhalt": z.inhalt,
            "ende": z.ende.code(),
        }));
    }
    Value::Array(out)
}

pub(crate) fn db_err(e: String) -> DbError {
    DbError::new("LINEFS", e)
}
