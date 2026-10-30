//! S1 — Zeilen-Kern im DB-Node: Editor-Sitzungen, anlegen/oeffnen/setzen/
//! einfuegen/loeschen/schliessen/rendere/lesen. Commits laufen als EINE
//! WAL-Nummer (art = linefs) ueber denselben Ein-Schreiber-Pfad wie SQL.

use super::linefs_common::{db_err, policy};
use super::linefs_ordner_read::pruefe_integritaet;
use super::linefs_pfad::pruefe_name;
use super::linefs_rows::{
    planung::plane_commit_daten, scheide, zerlege, Aktion, LinefsAktion, LinefsRequest, ZeileStand,
};
use super::types::DbResult;
use super::DbNode;
use serde_json::{json, Value};

/// Editor-Sitzung im RAM (keine Datei im Dateisystem).
#[derive(Clone, Debug)]
pub struct Sitzung {
    pub datei_id: i64,
    pub name: String,
    pub art: String,
    pub basis: i64,
    pub zeilen: Vec<ZeileStand>,
    pub urheber: String,
}

fn ts() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl DbNode {
    /// Einheitlicher Einstieg fuer die Befehls-Matrix.
    pub async fn linefs(&self, req: LinefsRequest) -> DbResult<Value> {
        let db = req.db_id.clone();
        let s = req.session_id.clone();
        match req.aktion {
            LinefsAktion::LinefsAnlegen { name, art, text, urheber, ordner_id } => {
                self.linefs_anlegen(&db, &s, &name, &art, &text, &urheber, ordner_id).await
            }
            LinefsAktion::LinefsOeffnen { pfad } => self.linefs_oeffnen(&db, &s, &pfad),
            LinefsAktion::LinefsZeileSetzen { nr, inhalt } => {
                self.linefs_setzen(&db, &s, nr, &inhalt)
            }
            LinefsAktion::LinefsEinfuegen { nr, inhalt } => {
                self.linefs_einfuegen(&db, &s, nr, &inhalt)
            }
            LinefsAktion::LinefsZeileLoeschen { nr } => self.linefs_loeschen(&db, &s, nr),
            LinefsAktion::LinefsSchliessen => self.linefs_schliessen(&db, &s).await,
            LinefsAktion::LinefsRendere { pfad } => self.linefs_rendere(&db, &pfad),
            LinefsAktion::LinefsLesen { pfad, von, bis } => self.linefs_lesen(&db, &s, &pfad, von, bis),
            LinefsAktion::LinefsSeiten { pfad } => self.linefs_seiten(&db, &pfad),
            LinefsAktion::LinefsHistorie { pfad, nr, schluessel } => {
                self.linefs_historie(&db, &s, &pfad, nr, schluessel)
            }
            LinefsAktion::LinefsStandZuZeitpunkt { pfad, fassung } => {
                self.linefs_stand_zu_zeitpunkt(&db, &pfad, fassung)
            }
            LinefsAktion::LinefsKettePruefen { pfad } => self.linefs_kette_pruefen(&db, &pfad),
            LinefsAktion::LinefsSuchen { muster, pfad } => {
                self.linefs_suchen(&db, &s, &pfad, &muster)
            }
            LinefsAktion::LinefsErsetzen { suche, ersatz } => {
                self.linefs_ersetzen(&db, &s, &suche, &ersatz)
            }
            LinefsAktion::LinefsSpeichern => self.linefs_speichern(&db, &s),
            LinefsAktion::LinefsUmbenennen { pfad, neu } => {
                self.linefs_umbenennen(&db, &s, &pfad, &neu).await
            }
            LinefsAktion::LinefsRenderFuerProzess { pfad, prozess_id } => {
                self.linefs_render_fuer_prozess(&db, &pfad, &prozess_id)
            }
            LinefsAktion::LinefsProzessEnde { prozess_id } => self.linefs_prozess_ende(&prozess_id),
            a @ (LinefsAktion::LinefsBinaerHochladen { .. }
            | LinefsAktion::LinefsBinaerZeigen { .. }
            | LinefsAktion::LinefsBinaerHolen { .. }
            | LinefsAktion::LinefsUebergangZuBinaer { .. }
            | LinefsAktion::LinefsUebergangZuText { .. }) => {
                self.linefs_binaer(&db, &s, a).await
            }
            LinefsAktion::OrdnerAnlegen { eltern_id, name } => {
                self.ordner_anlegen(&db, &s, eltern_id, &name).await
            }
            LinefsAktion::OrdnerVerschieben { id, neuer_eltern_id } => {
                self.ordner_verschieben(&db, &s, id, neuer_eltern_id).await
            }
            LinefsAktion::OrdnerUmbenennen { id, name } => {
                self.ordner_umbenennen(&db, &s, id, &name).await
            }
            LinefsAktion::OrdnerListen { eltern_id } => self.ordner_listen(&db, eltern_id),
            LinefsAktion::OrdnerPfadAufloesen { pfad } => {
                self.ordner_pfad_aufloesen(&db, &pfad)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn linefs_anlegen(
        &self, db: &str, session: &str, name: &str, art: &str, text: &str,
        urheber: &str, ordner_id: Option<i64>,
    ) -> DbResult<Value> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        match scheide::pruefe(text.as_bytes()) {
            scheide::Urteil::Text => {}
            scheide::Urteil::Binaer => {
                return Err(db_err("BINAER: Null-Byte — linefs_binaer_hochladen nutzen".into()))
            }
            scheide::Urteil::Deckel(m) => return Err(db_err(m.into())),
        }
        pruefe_name(name).map_err(db_err)?;
        let art = if art.is_empty() { "dokument" } else { art };
        let ordner_id = ordner_id.unwrap_or(0);
        let conn = h.readonly()?;
        pruefe_integritaet(&conn).map_err(db_err)?;
        if ordner_id != 0 {
            let n: i64 = conn
                .query_row("SELECT count(*) FROM ordner WHERE id = ?1", [ordner_id], |r| r.get(0))
                .map_err(|e| db_err(e.to_string()))?;
            if n == 0 {
                return Err(db_err(format!("Ordner {ordner_id} existiert nicht")));
            }
        }
        let da: i64 = conn
            .query_row(
                "SELECT count(*) FROM dateien WHERE ordner_id = ?1 AND name = ?2",
                rusqlite::params![ordner_id, name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if da > 0 {
            return Err(db_err(format!("Datei existiert bereits: {name}")));
        }
        let datei_id: i64 = conn
            .query_row("SELECT COALESCE(MAX(datei_id),0)+1 FROM dateien", [], |r| r.get(0))
            .map_err(|e| db_err(e.to_string()))?;
        let t = ts();
        let kopf = super::linefs_rows::DateiKopf {
            name: name.to_string(), art: art.to_string(), fassung: 0,
            hashkette: String::new(), ordner_id,
        };
        let ziel: Vec<ZeileStand> = zerlege(text)
            .into_iter()
            .map(|z| ZeileStand { schluessel: None, inhalt: z.inhalt, ende: z.ende, geloescht: false })
            .collect();
        let mut ops = vec![Aktion {
            sql: "INSERT INTO dateien (datei_id, name, art, ordner_id, status, fassung, hashkette, ts, urheber)
                  VALUES (?1,?2,?3,?4,'text',0,'',?5,?6)".into(),
            params: vec![json!(datei_id), json!(name), json!(art), json!(ordner_id), json!(t), json!(urheber)],
        }];
        ops.extend(plane_commit_daten(&kopf, datei_id, 0, &[], &ziel, urheber, &t, &policy(&h.cfg)).map_err(db_err)?);
        let out = h.write_ops(session, ops).await?;
        Ok(json!({"datei_id": datei_id, "name": name, "art": art, "ordner_id": ordner_id,
                  "fassung": if ziel.is_empty() {0} else {1}, "wal_nr": out.wal_nr}))
    }

}
