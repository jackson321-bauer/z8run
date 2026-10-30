//! S1 Lese-Pfad: oeffnen (Sitzung), rendere (byte-identisch), lesen (Bereich).

use super::linefs_common::{
    db_err, index_fuer_nr, kopf, lese_stand, policy, pruefe_einzelzeile, rendere, sitzung_key,
    zeilen_json,
};
use super::linefs_pfad::datei_id_fuer_pfad;
use super::linefs::Sitzung;
use super::linefs_ordner_read::pruefe_integritaet;
use super::linefs_rows::planung::plane_commit_daten;
use super::types::DbResult;
use super::DbNode;
use serde_json::{json, Value};

fn ts() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl DbNode {
    pub(crate) fn linefs_oeffnen(&self, db: &str, session: &str, pfad: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let conn = h.readonly()?;
        let datei_id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let (k, zeilen) = lese_stand(&conn, datei_id).map_err(db_err)?;
        let sitzung = Sitzung {
            datei_id, name: k.name.clone(), art: k.art.clone(), basis: k.fassung,
            zeilen: zeilen.clone(), urheber: "session".into(),
        };
        self.sitzungen.lock().unwrap().insert(sitzung_key(db, session), sitzung);
        Ok(json!({"datei_id": datei_id, "name": k.name, "art": k.art,
                  "basis": k.fassung, "zeilen": zeilen_json(&zeilen)}))
    }

    pub(crate) fn mit_sitzung<T>(&self, db: &str, session: &str, f: impl FnOnce(&mut Sitzung) -> DbResult<T>) -> DbResult<T> {
        let mut map = self.sitzungen.lock().unwrap();
        let s = map.get_mut(&sitzung_key(db, session))
            .ok_or_else(|| db_err("KEINE_SITZUNG: zuerst linefs_oeffnen".into()))?;
        f(s)
    }

    pub(crate) fn linefs_setzen(&self, db: &str, session: &str, nr: i64, inhalt: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        pruefe_einzelzeile(inhalt).map_err(db_err)?;
        self.mit_sitzung(db, session, |s| {
            let i = index_fuer_nr(&s.zeilen, nr).map_err(db_err)?;
            s.zeilen[i].inhalt = inhalt.to_string();
            Ok(json!({"nr": nr, "gesetzt": true}))
        })
    }

    pub(crate) fn linefs_einfuegen(&self, db: &str, session: &str, nr: i64, inhalt: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        pruefe_einzelzeile(inhalt).map_err(db_err)?;
        self.mit_sitzung(db, session, |s| {
            let sichtbar = s.zeilen.iter().filter(|z| !z.geloescht).count() as i64;
            if nr < 1 || nr > sichtbar + 1 {
                return Err(db_err(format!("Einfuege-Position {nr} ungueltig (1..{})", sichtbar + 1)));
            }
            let idx = if nr == sichtbar + 1 { s.zeilen.len() } else { index_fuer_nr(&s.zeilen, nr).map_err(db_err)? };
            let ende = s.zeilen.get(idx.saturating_sub(1)).or_else(|| s.zeilen.get(idx))
                .map(|z| z.ende).unwrap_or(super::linefs_rows::Ende::Lf);
            s.zeilen.insert(idx, super::linefs_rows::ZeileStand { schluessel: None, inhalt: inhalt.to_string(), ende, geloescht: false });
            Ok(json!({"nr": nr, "eingefuegt": true}))
        })
    }

    pub(crate) fn linefs_loeschen(&self, db: &str, session: &str, nr: i64) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        self.mit_sitzung(db, session, |s| {
            let i = index_fuer_nr(&s.zeilen, nr).map_err(db_err)?;
            s.zeilen[i].geloescht = true;
            Ok(json!({"nr": nr, "geloescht": true}))
        })
    }

    pub(crate) async fn linefs_schliessen(&self, db: &str, session: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let key = sitzung_key(db, session);
        let sitzung = self.sitzungen.lock().unwrap().get(&key).cloned()
            .ok_or_else(|| db_err("KEINE_SITZUNG: zuerst linefs_oeffnen".into()))?;
        let conn = h.readonly()?;
        pruefe_integritaet(&conn).map_err(db_err)?;
        let k = kopf(&conn, sitzung.datei_id).map_err(db_err)?;
        let ist = super::linefs_common::lese_ist(&conn, sitzung.datei_id).map_err(db_err)?;
        let t = ts();
        let ops = plane_commit_daten(
            &k, sitzung.datei_id, sitzung.basis, &ist, &sitzung.zeilen,
            &sitzung.urheber, &t, &policy(&h.cfg),
        ).map_err(db_err)?;
        let out = h.write_ops(session, ops).await?;
        self.sitzungen.lock().unwrap().remove(&key);
        let fassung = if out.rows_affected == 0 { k.fassung } else { k.fassung + 1 };
        Ok(json!({"datei_id": sitzung.datei_id, "fassung": fassung, "wal_nr": out.wal_nr,
                  "noop": out.rows_affected == 0}))
    }

    pub(crate) fn linefs_rendere(&self, db: &str, pfad: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
        let text = rendere(&conn, id).map_err(db_err)?;
        Ok(json!({"datei_id": id, "text": text}))
    }

    pub(crate) fn linefs_lesen(
        &self, db: &str, session: &str, pfad: &str, von: Option<i64>, bis: Option<i64>,
    ) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let zeilen = if pfad.is_empty() {
            self.sitzungen.lock().unwrap().get(&sitzung_key(db, session))
                .map(|s| s.zeilen.clone())
                .ok_or_else(|| db_err("KEINE_SITZUNG oder pfad fehlt".into()))?
        } else {
            let id = datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?;
            lese_stand(&conn, id).map_err(db_err)?.1
        };
        let von = von.unwrap_or(1).max(1);
        let bis = bis.unwrap_or(i64::MAX);
        let mut out = Vec::new();
        let mut nr = 0i64;
        for z in zeilen.iter().filter(|z| !z.geloescht) {
            nr += 1;
            if nr >= von && nr <= bis {
                out.push(json!({"nr": nr, "schluessel": z.schluessel, "inhalt": z.inhalt, "ende": z.ende.code()}));
            }
        }
        Ok(json!({"zeilen": out}))
    }
}
