//! BLOB-MANAGER: verschlüsselte Dateien über das bestehende StorageBackend.
//! Aufsatz auf die dbnode-Engine — Meta bleibt Zeile (WAL/Epochen), Rohdaten
//! liegen NIE in SQLite, sondern als Chiffre-Parts im Backend. RSS flach:
//! Upload/Download arbeiten in festen Parts (1 MiB), nie am Stück.

use crate::dbnode::blob_io::{
    blob_prefix, decrypt_part, open_db_key, part_key, seal_db_key, upload_parts,
};
use crate::dbnode::blob_meta::{insert_meta, load_meta, row_to_meta, BLOB_META_TABLE};
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::{DbHandle, DbNode};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub use crate::dbnode::blob_io::BLOB_PART_SIZE;
pub use crate::dbnode::blob_meta::{BlobMeta, BLOB_SESSION_TABLE};

impl DbNode {
    pub async fn blob_put_bytes(
        &self, db: &str, session: &str, owner: &str, name: &str, mime: &str, data: &[u8],
    ) -> DbResult<BlobMeta> {
        let mut cur = std::io::Cursor::new(data);
        self.blob_put_reader(db, session, owner, name, mime, &mut cur).await
    }

    pub async fn blob_put_file(
        &self, db: &str, session: &str, owner: &str, name: &str, mime: &str,
        path: &std::path::Path,
    ) -> DbResult<BlobMeta> {
        let mut f = std::fs::File::open(path)
            .map_err(|e| DbError::new("BLOB_INPUT", format!("{}: {e}", path.display())))?;
        self.blob_put_reader(db, session, owner, name, mime, &mut f).await
    }

    pub async fn blob_put_reader<R: Read>(
        &self, db: &str, session: &str, owner: &str, name: &str, mime: &str, reader: &mut R,
    ) -> DbResult<BlobMeta> {
        let h = self.get(db)?;
        // Fail-fast: Meta-Zeilen sind Ein-Schreiber (Reservierungspflicht).
        h.begin_write(session)?;
        h.end_write();
        let blob_id = uuid::Uuid::new_v4().to_string();
        let content_key: [u8; 32] = rand::random();
        let aad_ctx = format!("{db}:{blob_id}");
        let (parts, groesse, sha) =
            upload_parts(&h, &blob_id, &content_key, &aad_ctx, reader).await?;
        let huelleref = seal_db_key(&h, &blob_id, &content_key)?;
        let meta = BlobMeta {
            blob_id: blob_id.clone(),
            name: name.to_string(),
            mime: mime.to_string(),
            groesse,
            sha256_klartext: sha,
            content_key_huellereferenz: huelleref,
            storage_uri: format!("blobs/{db}/{blob_id}"),
            epoch: h.status().wal_stand + 1,
            owner: owner.to_string(),
            parts,
            session_id: None,
            chunk_index: None,
            dauer_ms: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        insert_meta(&h, session, &meta).await?;
        Ok(meta)
    }

    pub fn blob_list(&self, db: &str) -> DbResult<Vec<BlobMeta>> {
        let h = self.get(db)?;
        let q = h.query(
            &format!("SELECT {} FROM {BLOB_META_TABLE} ORDER BY created_at, blob_id",
                     crate::dbnode::blob_meta::META_COLS),
            &[],
        )?;
        Ok(q.rows.iter().map(|r| row_to_meta(&q.columns, r)).collect())
    }

    pub async fn blob_get_to_writer<W: Write>(
        &self, db: &str, blob_id: &str, sink: &mut W,
    ) -> DbResult<BlobMeta> {
        let h = self.get(db)?;
        let meta = load_meta(&h, blob_id)?;
        let (key, aad_ctx) = resolve_key(&h, db, &meta)?;
        let mut sha = Sha256::new();
        let mut size = 0u64;
        for part in 0..meta.parts {
            let sealed = h
                .storage
                .read(&part_key(db, blob_id, part))
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

    /// Konsistente Reihenfolge: ERST Meta-Zeile (WAL), DANN Backend-Parts.
    pub async fn blob_delete(&self, db: &str, session: &str, blob_id: &str) -> DbResult<u64> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let meta = load_meta(&h, blob_id)?;
        h.write(
            session,
            &format!("DELETE FROM {BLOB_META_TABLE} WHERE blob_id = ?1"),
            vec![json!(blob_id)],
        )
        .await?;
        for part in 0..meta.parts {
            h.storage.delete(&part_key(db, blob_id, part)).await?;
        }
        Ok(meta.parts)
    }

    /// Orphan-GC: Backend-Objekte ohne Meta-Zeile werden entfernt.
    pub async fn blob_gc(&self, db: &str) -> DbResult<Vec<String>> {
        let h = self.get(db)?;
        let known: std::collections::HashSet<String> =
            self.blob_list(db)?.into_iter().map(|m| m.blob_id).collect();
        let prefix = blob_prefix(db);
        let keys = h.storage.list(&prefix).await?;
        let mut deleted = Vec::new();
        for key in keys {
            let blob_id = key
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split('/').next())
                .unwrap_or_default()
                .to_string();
            if blob_id.is_empty() || known.contains(&blob_id) {
                continue;
            }
            h.storage.delete(&key).await?;
            deleted.push(key);
        }
        Ok(deleted)
    }
}

fn resolve_key(h: &DbHandle, db: &str, meta: &BlobMeta) -> DbResult<([u8; 32], String)> {
    match (&meta.session_id, meta.chunk_index) {
        (Some(sid), Some(idx)) => {
            let sk = crate::dbnode::blob_stream::session_content_key(h, sid)?;
            let info = format!("chunk:{sid}:{idx}");
            Ok((crate::dbnode::blob_io::derive(&sk, info.as_bytes()), info))
        }
        _ => {
            let ck = open_db_key(h, &meta.blob_id, &meta.content_key_huellereferenz)?;
            Ok((ck, format!("{db}:{}", meta.blob_id)))
        }
    }
}
