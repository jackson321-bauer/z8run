//! Matrix-Editierbefehle (Session): suchen, ersetzen, speichern.

use super::linefs_common::{db_err, lese_stand, sitzung_key};
use super::linefs_pfad::datei_id_fuer_pfad;
use super::linefs_rows::{als_zeilen, haenge_zusammen, scheide};
use super::types::DbResult;
use super::DbNode;
use serde_json::{json, Value};

impl DbNode {
    pub(crate) fn linefs_suchen(&self, db: &str, session: &str, pfad: &str, muster: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        let conn = h.readonly()?;
        let zeilen = if pfad.is_empty() {
            self.sitzungen.lock().unwrap().get(&sitzung_key(db, session))
                .map(|s| s.zeilen.clone())
                .ok_or_else(|| db_err("KEINE_SITZUNG oder pfad fehlt".into()))?
        } else {
            lese_stand(&conn, datei_id_fuer_pfad(&conn, pfad).map_err(db_err)?).map_err(db_err)?.1
        };
        let mut out = Vec::new();
        let mut nr = 0i64;
        for z in zeilen.iter().filter(|z| !z.geloescht) {
            nr += 1;
            if z.inhalt.contains(muster) {
                out.push(json!({"nr": nr, "inhalt": z.inhalt}));
            }
        }
        Ok(json!({"treffer": out}))
    }

    pub(crate) fn linefs_ersetzen(&self, db: &str, session: &str, suche: &str, ersatz: &str) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        super::linefs_common::pruefe_einzelzeile(ersatz).map_err(db_err)?;
        if suche.is_empty() {
            return Err(db_err("leerer Suchtext".into()));
        }
        self.mit_sitzung(db, session, |s| {
            let mut n = 0usize;
            for z in s.zeilen.iter_mut().filter(|z| !z.geloescht) {
                n += z.inhalt.matches(suche).count();
                z.inhalt = z.inhalt.replace(suche, ersatz);
            }
            Ok(json!({"ersetzt": n}))
        })
    }

    pub(crate) fn linefs_speichern(&self, db: &str, session: &str) -> DbResult<Value> {
        let _h = self.get(db)?;
        let s = self.sitzungen.lock().unwrap().get(&sitzung_key(db, session)).cloned()
            .ok_or_else(|| db_err("KEINE_SITZUNG".into()))?;
        let text = haenge_zusammen(&als_zeilen(&s.zeilen));
        match scheide::pruefe(text.as_bytes()) {
            scheide::Urteil::Deckel(m) => Err(db_err(m.into())),
            scheide::Urteil::Binaer => Err(db_err("DECKEL: Binaer im Textstand".into())),
            scheide::Urteil::Text => Ok(json!({"ok": true})),
        }
    }

}
