//! BLOB-MANAGER: verschlüsselte Dateien über das StorageBackend.
//! Rohdaten liegen NIE in SQLite, sondern als Chiffre-Parts im Backend.
//! Dedup: identischer Klartext-Hash teilt sich EIN Backend-Objekt
//! (linefs_blobhash haelt refcount); Reihenfolge beim Loeschen:
//! Meta zuerst, dann refcount, erst bei 0 das Backend-Objekt.

use crate::dbnode::blob_io::{blob_prefix, decrypt_part, open_db_key, part_key};
use crate::dbnode::blob_meta::{load_meta, row_to_meta, BLOB_META_TABLE, META_COLS};
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::{DbHandle, DbNode};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;

pub use crate::dbnode::blob_io::BLOB_PART_SIZE;
pub use crate::dbnode::blob_meta::{BlobMeta, BLOB_SESSION_TABLE};

fn objekt_id(storage_uri: &str) -> String {
    storage_uri.rsplit('/').next().unwrap_or_default().to_string()
}

impl DbNode {
    pub fn blob_list(&self, db: &str) -> DbResult<Vec<BlobMeta>> {
        let h = self.get(db)?;
        let q = h.query(
            &format!("SELECT {META_COLS} FROM {BLOB_META_TABLE} ORDER BY created_at, blob_id"),
            &[],
        )?;
        Ok(q.rows.iter().map(|r| row_to_meta(&q.columns, r)).collect())
    }

    pub async fn blob_get_to_writer<W: Write>(
        &self, db: &str, blob_id: &str, sink: &mut W,
    ) -> DbResult<BlobMeta> {
        let h = self.get(db)?;
        let meta = load_meta(&h, blob_id)?;
        let (key, aad_ctx, obj) = resolve_key(&h, db, &meta)?;
        let mut sha = Sha256::new();
        let mut size = 0u64;
        for part in 0..meta.parts {
            let sealed = h
                .storage
                .read(&part_key(db, &obj, part))
                .await?
                .ok_or_else(|| DbError::new("BLOB_MISSING", format!("Part {part} fehlt")))?;
            let plain = decrypt_part(&key, &aad_ctx, part, &sealed)?;
            sha.update(&plain);
            size += plain.len() as u64;
            sink.write_all(&plain)
                .map_err(|e| DbError::new("BLOB_SINK", format!("schreiben: {e}")))?;
        }
        if size != meta.groesse || hex::encode(sha.finalize()) != meta.sha256_klartext {
            return Err(DbError::new("BLOB_INTEGRITY", "SHA256/Größe stimmt nicht"));
        }
        Ok(meta)
    }

    pub async fn blob_get_bytes(&self, db: &str, blob_id: &str) -> DbResult<Vec<u8>> {
        let mut out = Vec::new();
        self.blob_get_to_writer(db, blob_id, &mut out).await?;
        Ok(out)
    }

    pub async fn blob_get_to_file(
        &self, db: &str, blob_id: &str, path: &std::path::Path,
    ) -> DbResult<BlobMeta> {
        let mut f = std::fs::File::create(path)
            .map_err(|e| DbError::new("BLOB_SINK", format!("{}: {e}", path.display())))?;
        let meta = self.blob_get_to_writer(db, blob_id, &mut f).await?;
        f.flush().map_err(|e| DbError::new("BLOB_SINK", e.to_string()))?;
        Ok(meta)
    }

    /// ERST Meta-Zeile (WAL), DANN refcount, erst bei 0 die Backend-Parts.
    pub async fn blob_delete(&self, db: &str, session: &str, blob_id: &str) -> DbResult<u64> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let meta = load_meta(&h, blob_id)?;
        let obj = objekt_id(&meta.storage_uri);
        let q = h.query(
            "SELECT refcount FROM linefs_blobhash WHERE sha256=?1",
            &[json!(meta.sha256_klartext)],
        )?;
        let refcount = q.rows.first().and_then(|r| r[0].as_i64());
        h.write(
            session,
            &format!("DELETE FROM {BLOB_META_TABLE} WHERE blob_id = ?1"),
            vec![json!(blob_id)],
        )
        .await?;
        match refcount {
            Some(rc) if rc > 1 => {
                h.write(session,
                    "UPDATE linefs_blobhash SET refcount=refcount-1 WHERE sha256=?1",
                    vec![json!(meta.sha256_klartext)]).await?;
            }
            _ => {
                // Reihenfolge FEST: Meta -> refcount/Hash-Zeile -> Backend.
                // Crash davor hinterlaesst nur ein GC-bares Orphan, nie eine
                // stale Hash-Zeile (die spaetere Dedup-Puts blockieren wuerde).
                if refcount.is_some() {
                    h.write(session,
                        "DELETE FROM linefs_blobhash WHERE sha256=?1",
                        vec![json!(meta.sha256_klartext)]).await?;
                }
                for part in 0..meta.parts {
                    h.storage.delete(&part_key(db, &obj, part)).await?;
                }
            }
        }
        Ok(meta.parts)
    }

    /// Orphan-GC: Backend-Objekte ohne referenzierende Metazeile entfernen.
    pub async fn blob_gc(&self, db: &str) -> DbResult<Vec<String>> {
        let h = self.get(db)?;
        let bekannt: std::collections::HashSet<String> =
            self.blob_list(db)?.into_iter().map(|m| m.storage_uri).collect();
        let prefix = blob_prefix(db);
        let keys = h.storage.list(&prefix).await?;
        let mut deleted = Vec::new();
        for key in keys {
            let obj = key
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split('/').next())
                .unwrap_or_default();
            if obj.is_empty() || bekannt.contains(&format!("{prefix}{obj}")) {
                continue;
            }
            h.storage.delete(&key).await?;
            deleted.push(key);
        }
        Ok(deleted)
    }
}

fn resolve_key(h: &DbHandle, db: &str, meta: &BlobMeta) -> DbResult<([u8; 32], String, String)> {
    match (&meta.session_id, meta.chunk_index) {
        (Some(sid), Some(idx)) => {
            let sk = crate::dbnode::blob_stream::session_content_key(h, sid)?;
            let info = format!("chunk:{sid}:{idx}");
            Ok((crate::dbnode::blob_io::derive(&sk, info.as_bytes()), info, meta.blob_id.clone()))
        }
        _ => {
            let obj = objekt_id(&meta.storage_uri);
            let ck = open_db_key(h, &obj, &meta.content_key_huellereferenz)?;
            Ok((ck, format!("{db}:{obj}"), obj))
        }
    }
}
