//! Binär-Zeilen der Matrix — einheitlich ueber linefs_blobs (kein
//! binaer_s3/Secret.db). Uebergaenge sind bewusst und epochen-belegt.

use super::linefs_common::{db_err, kopf, lese_ist, policy, rendere};
use super::linefs_ordner_read::pruefe_integritaet;
use super::linefs_pfad::datei_id_fuer_pfad;
use super::linefs_rows::{planung::plane_commit_daten, scheide, zerlege, Aktion, LinefsAktion, ZeileStand};
use super::types::DbResult;
use super::DbNode;
use base64::Engine;
use serde_json::{json, Value};

fn ts() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn meta_json(m: &super::BlobMeta) -> Value {
    json!({
        "blob_id": m.blob_id, "name": m.name, "mime": m.mime,
        "groesse": m.groesse, "sha256": m.sha256_klartext,
        "storage_uri": m.storage_uri, "epoch": m.epoch, "parts": m.parts,
    })
}

fn finde_meta(node: &DbNode, db: &str, blob_id: &str) -> DbResult<super::BlobMeta> {
    node.blob_list(db)?
        .into_iter()
        .find(|m| m.blob_id == blob_id)
        .ok_or_else(|| db_err("BLOB_NOT_FOUND".into()))
}

impl DbNode {
    pub(crate) async fn linefs_binaer(
        &self, db: &str, session: &str, aktion: LinefsAktion,
    ) -> DbResult<Value> {
        match aktion {
            LinefsAktion::LinefsBinaerHochladen { name, mime, datei_pfad, bytes_b64, owner } => {
                let data = if let Some(p) = datei_pfad {
                    std::fs::read(&p).map_err(|e| db_err(format!("{p}: {e}")))?
                } else if let Some(b) = bytes_b64 {
                    base64::engine::general_purpose::STANDARD
                        .decode(b)
                        .map_err(|e| db_err(format!("bytes_b64: {e}")))?
                } else {
                    return Err(db_err("datei_pfad oder bytes_b64 noetig".into()));
                };
                let m = self.blob_put_bytes(db, session, &owner, &name, &mime, &data).await?;
                Ok(meta_json(&m))
            }
            LinefsAktion::LinefsBinaerZeigen { blob_id } => {
                let list = self.blob_list(db)?;
                match blob_id {
                    Some(id) => list.into_iter().find(|m| m.blob_id == id)
                        .map(|m| meta_json(&m))
                        .ok_or_else(|| db_err("BLOB_NOT_FOUND".into())),
                    None => Ok(json!({"blobs": list.iter().map(meta_json).collect::<Vec<_>>()})),
                }
            }
            LinefsAktion::LinefsBinaerHolen { blob_id, ziel_pfad } => {
                if let Some(p) = ziel_pfad {
                    let m = self.blob_get_to_file(db, &blob_id, std::path::Path::new(&p)).await?;
                    Ok(json!({"meta": meta_json(&m), "ziel": p}))
                } else {
                    let m = finde_meta(self, db, &blob_id)?;
                    let bytes = self.blob_get_bytes(db, &blob_id).await?;
                    let mut out = meta_json(&m);
                    out["bytes_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
                    Ok(out)
                }
            }
            LinefsAktion::LinefsUebergangZuBinaer { pfad, name, mime } => {
                let h = self.get(db)?;
                h.begin_write(session)?;
                h.end_write();
                let conn = h.readonly()?;
                pruefe_integritaet(&conn).map_err(db_err)?;
                let id = datei_id_fuer_pfad(&conn, &pfad).map_err(db_err)?;
                let text = rendere(&conn, id).map_err(db_err)?;
                let k = kopf(&conn, id).map_err(db_err)?;
                let ist = lese_ist(&conn, id).map_err(db_err)?;
                drop(conn);
                let m = self.blob_put_bytes(db, session, "linefs", &name, &mime, text.as_bytes()).await?;
                let t = ts();
                let mut ops = plane_commit_daten(&k, id, k.fassung, &ist, &[], "linefs", &t, &policy(&h.cfg))
                    .map_err(db_err)?;
                ops.push(Aktion {
                    sql: "UPDATE dateien SET status='binaer', binaer_blob_id=?1, binaer_sha=?2 WHERE datei_id=?3".into(),
                    params: vec![json!(m.blob_id), json!(m.sha256_klartext), json!(id)],
                });
                let out = h.write_ops(session, ops).await?;
                Ok(json!({"datei_id": id, "status": "binaer", "blob": meta_json(&m), "wal_nr": out.wal_nr}))
            }
            LinefsAktion::LinefsUebergangZuText { pfad } => {
                let h = self.get(db)?;
                h.begin_write(session)?;
                h.end_write();
                let conn = h.readonly()?;
                pruefe_integritaet(&conn).map_err(db_err)?;
                let id = datei_id_fuer_pfad(&conn, &pfad).map_err(db_err)?;
                let k = kopf(&conn, id).map_err(db_err)?;
                let (blob_id, status): (Option<String>, String) = conn
                    .query_row("SELECT binaer_blob_id, status FROM dateien WHERE datei_id=?1", [id], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .map_err(|e| db_err(e.to_string()))?;
                let ist = lese_ist(&conn, id).map_err(db_err)?;
                drop(conn);
                if status != "binaer" {
                    return Err(db_err("Datei ist nicht im Binaer-Status".into()));
                }
                let blob_id = blob_id.ok_or_else(|| db_err("binaer_blob_id fehlt".into()))?;
                let bytes = self.blob_get_bytes(db, &blob_id).await?;
                let text = match scheide::pruefe(&bytes) {
                    scheide::Urteil::Text => String::from_utf8(bytes).map_err(|e| db_err(e.to_string()))?,
                    scheide::Urteil::Deckel(m) => return Err(db_err(m.into())),
                    scheide::Urteil::Binaer => return Err(db_err("Binaerinhalt bleibt binaer".into())),
                };
                let t = ts();
                let ziel: Vec<ZeileStand> = zerlege(&text).into_iter()
                    .map(|z| ZeileStand { schluessel: None, inhalt: z.inhalt, ende: z.ende, geloescht: false })
                    .collect();
                let mut ops = plane_commit_daten(&k, id, k.fassung, &ist, &ziel, "linefs", &t, &policy(&h.cfg))
                    .map_err(db_err)?;
                ops.push(Aktion {
                    sql: "UPDATE dateien SET status='text' WHERE datei_id=?1".into(),
                    params: vec![json!(id)],
                });
                let out = h.write_ops(session, ops).await?;
                Ok(json!({"datei_id": id, "status": "text", "wal_nr": out.wal_nr}))
            }
            _ => Err(db_err("keine Binaer-Aktion".into())),
        }
    }
}
