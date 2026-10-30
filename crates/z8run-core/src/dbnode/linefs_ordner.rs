//! Ordner-API (S2): Baum als Wahrheit, Pfad nur als gerenderte Sicht.
//! Zyklen verboten, Tiefe/Name begrenzt, verwaiste Dateien verboten.

use super::linefs_common::db_err;
use super::linefs_ordner_read::pruefe_integritaet;
use super::linefs_pfad::{id_fuer, pfad_von_ordner, pruefe_name, MAX_TIEFE};
use super::linefs_rows::{schema::ORDNER_WURZEL, Aktion};
use super::types::DbResult;
use super::DbNode;
use rusqlite::Connection;
use serde_json::{json, Value};

/// Tiefe (auch fuer den Lesepfad).
pub(crate) fn tiefe(conn: &Connection, id: i64) -> Result<i64, String> {
    let mut cur = id;
    let mut d = 0i64;
    while cur != ORDNER_WURZEL {
        if d > MAX_TIEFE + 1 {
            return Err("Ordner-Baum zu tief / Zyklus".into());
        }
        let eltern: i64 = conn
            .query_row("SELECT eltern_id FROM ordner WHERE id = ?1", [cur], |r| r.get(0))
            .map_err(|_| format!("Ordner {cur} existiert nicht"))?;
        if eltern == cur {
            return Err("Ordner-Zyklus (selbst)".into());
        }
        cur = eltern;
        d += 1;
    }
    Ok(d)
}

fn max_tiefe_unter(conn: &Connection, id: i64) -> Result<i64, String> {
    let mut max = 0i64;
    let mut stmt = conn
        .prepare("SELECT id FROM ordner WHERE eltern_id = ?1")
        .map_err(|e| e.to_string())?;
    let kids: Vec<i64> = stmt
        .query_map([id], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for k in kids {
        max = max.max(1 + max_tiefe_unter(conn, k)?);
    }
    Ok(max)
}

fn ist_nachfahre(conn: &Connection, kandidat: i64, vorfahre: i64) -> Result<bool, String> {
    let mut cur = kandidat;
    let mut guard = 0;
    while cur != ORDNER_WURZEL {
        guard += 1;
        if guard > MAX_TIEFE + 2 {
            return Err("Ordner-Zyklus".into());
        }
        if cur == vorfahre {
            return Ok(true);
        }
        cur = conn
            .query_row("SELECT eltern_id FROM ordner WHERE id = ?1", [cur], |r| r.get(0))
            .map_err(|_| format!("Ordner {cur} existiert nicht"))?;
    }
    Ok(false)
}

/// Integritaet: keine verwaisten Dateien, keine fehlenden Eltern, keine Zyklen.
impl DbNode {
    pub async fn ordner_anlegen(
        &self, db: &str, session: &str, eltern_id: i64, name: &str,
    ) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        pruefe_name(name).map_err(db_err)?;
        let conn = h.readonly()?;
        pruefe_integritaet(&conn).map_err(db_err)?;
        if eltern_id != ORDNER_WURZEL {
            let n: i64 = conn
                .query_row("SELECT count(*) FROM ordner WHERE id = ?1", [eltern_id], |r| r.get(0))
                .map_err(|e| db_err(e.to_string()))?;
            if n == 0 {
                return Err(db_err(format!("Eltern-Ordner {eltern_id} existiert nicht")));
            }
        }
        if id_fuer(&conn, eltern_id, name).is_some() {
            return Err(db_err(format!("Ordner existiert bereits: {name}")));
        }
        let datei_kollision: i64 = conn
            .query_row(
                "SELECT count(*) FROM dateien WHERE ordner_id=?1 AND name=?2 AND geloescht=0",
                rusqlite::params![eltern_id, name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if datei_kollision > 0 {
            return Err(db_err(format!("Name im Ordner bereits als Datei belegt: {name}")));
        }
        if tiefe(&conn, eltern_id).map_err(db_err)? + 1 > MAX_TIEFE {
            return Err(db_err(format!("Pfad-Tiefe > {MAX_TIEFE}")));
        }
        let id: i64 = conn
            .query_row("SELECT COALESCE(MAX(id),0)+1 FROM ordner", [], |r| r.get(0))
            .map_err(|e| db_err(e.to_string()))?;
        let ops = vec![Aktion {
            sql: "INSERT INTO ordner (id, eltern_id, name) VALUES (?1, ?2, ?3)".into(),
            params: vec![json!(id), json!(eltern_id), json!(name)],
        }];
        let out = h.write_ops(session, ops).await?;
        Ok(json!({"id": id, "eltern_id": eltern_id, "name": name,
                  "pfad": pfad_von_ordner(&conn, id).map_err(db_err)?,
                  "wal_nr": out.wal_nr}))
    }

    pub async fn ordner_verschieben(
        &self, db: &str, session: &str, id: i64, neuer_eltern_id: i64,
    ) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let conn = h.readonly()?;
        pruefe_integritaet(&conn).map_err(db_err)?;
        tiefe(&conn, id).map_err(db_err)?;
        if neuer_eltern_id != ORDNER_WURZEL {
            tiefe(&conn, neuer_eltern_id).map_err(db_err)?;
        }
        if ist_nachfahre(&conn, neuer_eltern_id, id).map_err(db_err)? {
            return Err(db_err("ZYKLUS: Ordner kann nicht in sich selbst wandern".into()));
        }
        let neu_tiefe = tiefe(&conn, neuer_eltern_id).map_err(db_err)?
            + 1
            + max_tiefe_unter(&conn, id).map_err(db_err)?;
        if neu_tiefe > MAX_TIEFE {
            return Err(db_err(format!("Pfad-Tiefe > {MAX_TIEFE}")));
        }
        let ops = vec![Aktion {
            sql: "UPDATE ordner SET eltern_id = ?1 WHERE id = ?2".into(),
            params: vec![json!(neuer_eltern_id), json!(id)],
        }];
        let out = h.write_ops(session, ops).await?;
        Ok(json!({"id": id, "eltern_id": neuer_eltern_id,
                  "pfad": pfad_von_ordner(&conn, id).map_err(db_err)?,
                  "wal_nr": out.wal_nr}))
    }

    pub async fn ordner_umbenennen(
        &self, db: &str, session: &str, id: i64, name: &str,
    ) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        pruefe_name(name).map_err(db_err)?;
        let conn = h.readonly()?;
        pruefe_integritaet(&conn).map_err(db_err)?;
        let eltern: i64 = conn
            .query_row("SELECT eltern_id FROM ordner WHERE id = ?1", [id], |r| r.get(0))
            .map_err(|_| db_err(format!("Ordner {id} existiert nicht")))?;
        if let Some(anderer) = id_fuer(&conn, eltern, name) {
            if anderer != id {
                return Err(db_err(format!("Name existiert bereits: {name}")));
            }
        }
        let datei_kollision: i64 = conn
            .query_row(
                "SELECT count(*) FROM dateien WHERE ordner_id=?1 AND name=?2 AND geloescht=0",
                rusqlite::params![eltern, name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if datei_kollision > 0 {
            return Err(db_err(format!("Name im Ordner bereits als Datei belegt: {name}")));
        }
        let ops = vec![Aktion {
            sql: "UPDATE ordner SET name = ?1 WHERE id = ?2".into(),
            params: vec![json!(name), json!(id)],
        }];
        let out = h.write_ops(session, ops).await?;
        Ok(json!({"id": id, "name": name, "wal_nr": out.wal_nr}))
    }

}
