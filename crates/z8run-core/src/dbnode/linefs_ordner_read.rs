//! Ordner-Lesepfad: Integritaet, Baum-Liste, Pfad-Aufloesung.

use super::linefs_common::{db_err, kopf};
use super::linefs_ordner::tiefe;
use super::linefs_pfad::{datei_id_fuer_pfad, pfad_von_datei, pfad_von_ordner};
use super::linefs_rows::schema::ORDNER_WURZEL;
use super::types::DbResult;
use super::DbNode;
use rusqlite::Connection;
use serde_json::{json, Value};

pub(crate) fn pruefe_integritaet(conn: &Connection) -> Result<(), String> {
    let verwaist: i64 = conn
        .query_row(
            "SELECT count(*) FROM dateien d LEFT JOIN ordner o ON o.id = d.ordner_id
             WHERE d.ordner_id <> 0 AND o.id IS NULL",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if verwaist > 0 {
        return Err(format!("ORDNER-INTEGRITAET: {verwaist} verwaiste Datei(en)"));
    }
    let mut stmt = conn.prepare("SELECT id FROM ordner").map_err(|e| e.to_string())?;
    let ids: Vec<i64> = stmt
        .query_map([], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for id in ids {
        tiefe(conn, id)?;
    }
    Ok(())
}

fn baum(conn: &Connection, eltern: i64) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut stmt = conn
        .prepare("SELECT id, name FROM ordner WHERE eltern_id = ?1 ORDER BY name")
        .map_err(|e| e.to_string())?;
    let ordner: Vec<(i64, String)> = stmt
        .query_map([eltern], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for (id, name) in ordner {
        out.push(json!({
            "art": "ordner", "id": id, "name": name,
            "pfad": pfad_von_ordner(conn, id)?,
            "kinder": baum(conn, id)?,
        }));
    }
    let mut fstmt = conn
        .prepare("SELECT datei_id, name, fassung, art FROM dateien
                  WHERE ordner_id = ?1 AND geloescht = 0 ORDER BY name")
        .map_err(|e| e.to_string())?;
    let dateien: Vec<(i64, String, i64, String)> = fstmt
        .query_map([eltern], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for (id, name, fassung, art) in dateien {
        out.push(json!({
            "art": "datei", "datei_id": id, "name": name,
            "fassung": fassung, "datei_art": art,
        }));
    }
    Ok(out)
}


impl DbNode {
    pub fn ordner_listen(&self, db: &str, eltern_id: i64) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        if eltern_id != ORDNER_WURZEL {
            tiefe(&conn, eltern_id).map_err(db_err)?;
        }
        Ok(json!({
            "eltern_id": eltern_id,
            "pfad": pfad_von_ordner(&conn, eltern_id).map_err(db_err)?,
            "eintraege": baum(&conn, eltern_id).map_err(db_err)?,
        }))
    }

    pub fn ordner_pfad_aufloesen(&self, db: &str, pfad: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let datei_id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let k = kopf(&conn, datei_id).map_err(db_err)?;
        Ok(json!({
            "datei_id": datei_id,
            "pfad": pfad_von_datei(&conn, datei_id).map_err(db_err)?,
            "name": k.name, "art": k.art, "fassung": k.fassung,
            "ordner_id": k.ordner_id,
        }))
    }
}
