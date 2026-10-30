//! Matrix-Ergaenzungen: suchen, ersetzen, speichern, seiten, historie,
//! stand_zu_zeitpunkt, umbenennen, kette_pruefen, render_fuer_prozess.

use super::linefs_common::{db_err, kopf, lese_ist, rendere, sitzung_key, zeilen_json};
use super::linefs_pfad::{datei_id_fuer_pfad, pruefe_name};
use super::linefs_rows::{
    als_zeilen, fassung_aus_epochen, haenge_zusammen, historie_aus_epochen, kette_pruefen_daten,
    tabelle_seite, Aktion, EpocheRoh, KettenZeile,
};
use super::types::DbResult;
use super::DbNode;
use rusqlite::Connection;
use serde_json::{json, Value};

fn epochen(conn: &Connection, datei_id: i64, schluessel: Option<i64>, bis: Option<i64>) -> Result<Vec<EpocheRoh>, String> {
    let (sql, params): (&str, Vec<i64>) = match (schluessel, bis) {
        (Some(k), _) => (
            "SELECT schluessel,fassung,nr,inhalt,ende,geloescht FROM zeilen_epochen
             WHERE datei_id=?1 AND schluessel=?2 ORDER BY id",
            vec![datei_id, k],
        ),
        (None, Some(f)) => (
            "SELECT schluessel,fassung,nr,inhalt,ende,geloescht FROM zeilen_epochen
             WHERE datei_id=?1 AND fassung<=?2 ORDER BY id",
            vec![datei_id, f],
        ),
        (None, None) => (
            "SELECT schluessel,fassung,nr,inhalt,ende,geloescht FROM zeilen_epochen
             WHERE datei_id=?1 ORDER BY id",
            vec![datei_id],
        ),
    };
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            Ok(EpocheRoh {
                schluessel: r.get(0)?, fassung: r.get(1)?, nr: r.get(2)?,
                inhalt: r.get(3)?, ende: r.get(4)?, geloescht: r.get::<_, i64>(5)? != 0,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

impl DbNode {
    pub(crate) fn linefs_historie(
        &self, db: &str, session: &str, pfad: &str, nr: i64, schluessel: Option<i64>,
    ) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let id = if pfad.is_empty() {
            self.sitzungen.lock().unwrap().get(&sitzung_key(db, session))
                .map(|s| s.datei_id)
                .ok_or_else(|| db_err("KEINE_SITZUNG oder pfad fehlt".into()))?
        } else {
            datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?
        };
        let ist = lese_ist(&conn, id).map_err(db_err)?;
        let key = match schluessel {
            Some(k) => k,
            None => ist.iter().filter(|z| !z.geloescht).nth((nr - 1).max(0) as usize)
                .map(|z| z.schluessel)
                .ok_or_else(|| db_err(format!("Zeile {nr} nicht gefunden")))?,
        };
        let hist = historie_aus_epochen(&epochen(&conn, id, Some(key), None).map_err(db_err)?)
            .map_err(db_err)?;
        let out: Vec<Value> = hist.into_iter().map(|(f, i, e)| json!({
            "fassung": f, "inhalt": i, "ende": e.code()
        })).collect();
        Ok(json!({"datei_id": id, "schluessel": key, "historie": out}))
    }

    pub(crate) fn linefs_stand_zu_zeitpunkt(&self, db: &str, pfad: &str, fassung: i64) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let e = epochen(&conn, id, None, Some(fassung)).map_err(db_err)?;
        let stand = fassung_aus_epochen(&e);
        Ok(json!({"datei_id": id, "fassung": fassung, "zeilen": zeilen_json(&stand),
                  "text": haenge_zusammen(&als_zeilen(&stand))}))
    }

    pub(crate) fn linefs_kette_pruefen(&self, db: &str, pfad: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let mut stmt = conn
            .prepare("SELECT seite,schluessel,nr,seg,inhalt,ende,fassung,geloescht,ts,urheber,vor_hash,hash
                      FROM zeilen_epochen WHERE datei_id=?1 ORDER BY id")
            .map_err(|e| db_err(e.to_string()))?;
        let rows = stmt
            .query_map([id], |r| {
                Ok(KettenZeile {
                    seite: r.get(0)?, schluessel: r.get(1)?, nr: r.get(2)?, seg: r.get(3)?,
                    inhalt: r.get(4)?, ende: r.get(5)?, fassung: r.get(6)?,
                    geloescht: r.get::<_, i64>(7)? != 0, ts: r.get(8)?, urheber: r.get(9)?,
                    vor_hash: r.get(10)?, hash: r.get(11)?,
                })
            })
            .map_err(|e| db_err(e.to_string()))?;
        let zeilen: Vec<KettenZeile> = rows.collect::<Result<_, _>>().map_err(|e| db_err(e.to_string()))?;
        let kopf_hash: String = conn
            .query_row("SELECT hashkette FROM dateien WHERE datei_id=?1", [id], |r| r.get(0))
            .map_err(|e| db_err(e.to_string()))?;
        let gruen = kette_pruefen_daten(id, &zeilen, &kopf_hash);
        Ok(json!({"datei_id": id, "gruen": gruen, "glieder": zeilen.len()}))
    }

    pub(crate) fn linefs_seiten(&self, db: &str, pfad: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let mut stmt = conn
            .prepare("SELECT seite FROM seiten WHERE datei_id=?1 ORDER BY seite")
            .map_err(|e| db_err(e.to_string()))?;
        let seiten: Vec<i64> = stmt.query_map([id], |r| r.get(0))
            .map_err(|e| db_err(e.to_string()))?
            .collect::<Result<_, _>>().map_err(|e| db_err(e.to_string()))?;
        let mut out = Vec::new();
        for s in seiten {
            let t = tabelle_seite(id as u64, s as u32);
            let n: i64 = conn.query_row(&format!("SELECT count(*) FROM {t} WHERE geloescht=0"), [], |r| r.get(0))
                .unwrap_or(0);
            out.push(json!({"seite": s, "zeilen": n}));
        }
        Ok(json!({"datei_id": id, "seiten": out}))
    }

    pub(crate) async fn linefs_umbenennen(&self, db: &str, session: &str, pfad: &str, neu: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        pruefe_name(neu).map_err(db_err)?;
        let conn = h.readonly()?;
        let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let k = kopf(&conn, id).map_err(db_err)?;
        let da: i64 = conn.query_row(
            "SELECT count(*) FROM dateien WHERE ordner_id=?1 AND name=?2 AND datei_id<>?3",
            rusqlite::params![k.ordner_id, neu, id], |r| r.get(0),
        ).unwrap_or(0);
        if da > 0 {
            return Err(db_err(format!("Name existiert bereits: {neu}")));
        }
        let ops = vec![Aktion {
            sql: "UPDATE dateien SET name=?1 WHERE datei_id=?2".into(),
            params: vec![json!(neu), json!(id)],
        }];
        let out = h.write_ops(session, ops).await?;
        Ok(json!({"datei_id": id, "neu": neu, "wal_nr": out.wal_nr}))
    }

    pub(crate) fn linefs_render_fuer_prozess(&self, db: &str, pfad: &str, prozess_id: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let text = rendere(&conn, id).map_err(db_err)?;
        let dir = h.base_dir.join("tmp").join("linefs-render").join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).map_err(|e| db_err(format!("render mkdir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let datei = dir.join("inhalt");
        std::fs::write(&datei, text.as_bytes()).map_err(|e| db_err(format!("render write: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&datei, std::fs::Permissions::from_mode(0o600));
        }
        self.render_tmp.lock().unwrap().insert(prozess_id.to_string(), dir.clone());
        Ok(json!({"prozess_id": prozess_id, "pfad": datei.to_string_lossy(), "bytes": text.len()}))
    }

    pub(crate) fn linefs_prozess_ende(&self, prozess_id: &str) -> DbResult<Value> {
        let dir = self.render_tmp.lock().unwrap().remove(prozess_id);
        let mut weg = false;
        if let Some(d) = dir {
            weg = std::fs::remove_dir_all(&d).is_ok();
        }
        Ok(json!({"prozess_id": prozess_id, "weggeraeumt": weg, "rest": self.render_tmp.lock().unwrap().len()}))
    }
}
