//! Playlist-Wiedergabe, Finish, Delete und Session-Liste (Chunk-Streaming).

use crate::dbnode::blob_io::{decrypt_part, part_key};
use crate::dbnode::blob_meta::{load_meta, BLOB_META_TABLE, BLOB_SESSION_TABLE};
use crate::dbnode::blob_stream::{chunk_keys, load_session, row_to_session, session_content_key, SessionManifest, SESSION_COLS};
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::DbNode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

impl DbNode {
    /// Playlist: Chunks in Manifest-Reihenfolge, nahtlos entschlüsselt.
    pub async fn blob_session_get_to_writer<W: Write>(
        &self, db: &str, sid: &str, sink: &mut W,
    ) -> DbResult<SessionManifest> {
        let h = self.get(db)?;
        let m = load_session(&h, sid)?;
        let sk = session_content_key(&h, sid)?;
        let mut total = Sha256::new();
        for chunk_id in &m.chunk_ids {
            let meta = load_meta(&h, chunk_id)?;
            let idx = meta
                .chunk_index
                .ok_or_else(|| DbError::new("BLOB_SESSION", "Chunk ohne chunk_index"))?;
            let (key, aad_ctx) = chunk_keys(&sk, sid, idx);
            let mut sha = Sha256::new();
            let mut size = 0u64;
            for part in 0..meta.parts {
                let sealed = h
                    .storage
                    .read(&part_key(db, chunk_id, part))
                    .await?
                    .ok_or_else(|| DbError::new("BLOB_MISSING", "Chunk-Part fehlt"))?;
                let plain = decrypt_part(&key, &aad_ctx, part, &sealed)?;
                sha.update(&plain);
                total.update(&plain);
                size += plain.len() as u64;
                sink.write_all(&plain)
                    .map_err(|e| DbError::new("BLOB_SINK", format!("schreiben: {e}")))?;
            }
            if size != meta.groesse || hex::encode(sha.finalize()) != meta.sha256_klartext {
                return Err(DbError::new("BLOB_INTEGRITY", "Chunk-SHA256 stimmt nicht"));
            }
        }
        if !m.gesamt_sha256.is_empty() && hex::encode(total.finalize()) != m.gesamt_sha256 {
            return Err(DbError::new(
                "BLOB_INTEGRITY",
                "Gesamt-SHA256 stimmt nicht (Reihenfolge/Manipulation)",
            ));
        }
        Ok(m)
    }

    pub async fn blob_session_get_bytes(&self, db: &str, sid: &str) -> DbResult<Vec<u8>> {
        let mut out = Vec::new();
        self.blob_session_get_to_writer(db, sid, &mut out).await?;
        Ok(out)
    }

    /// Setzt gesamt_sha256 (SHA über die komplette Aufnahme) final.
    pub async fn blob_session_finish(
        &self, db: &str, session: &str, sid: &str,
    ) -> DbResult<SessionManifest> {
        // Kein Vollpuffer: die Wiedergabe fließt direkt in den Hash (RSS flach,
        // auch bei 2-h-Aufnahmen).
        let mut sink = HashSink(Sha256::new());
        let mut m = self.blob_session_get_to_writer(db, sid, &mut sink).await?;
        let sha = hex::encode(sink.0.finalize());
        let h = self.get(db)?;
        h.write(
            session,
            &format!("UPDATE {BLOB_SESSION_TABLE} SET gesamt_sha256 = ?1 WHERE session_id = ?2"),
            vec![json!(sha), json!(sid)],
        )
        .await?;
        m.gesamt_sha256 = sha;
        Ok(m)
    }

    /// Manifest zuerst (keine toten Referenzen), dann Chunk-Zeilen + Parts.
    pub async fn blob_session_delete(&self, db: &str, session: &str, sid: &str) -> DbResult<u64> {
        let h = self.get(db)?;
        let m = load_session(&h, sid)?;
        h.write(
            session,
            &format!("DELETE FROM {BLOB_SESSION_TABLE} WHERE session_id = ?1"),
            vec![json!(sid)],
        )
        .await?;
        let mut deleted = 0u64;
        for chunk_id in &m.chunk_ids {
            if let Ok(meta) = load_meta(&h, chunk_id) {
                h.write(
                    session,
                    &format!("DELETE FROM {BLOB_META_TABLE} WHERE blob_id = ?1"),
                    vec![json!(chunk_id)],
                )
                .await?;
                for part in 0..meta.parts {
                    h.storage.delete(&part_key(db, chunk_id, part)).await?;
                }
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    pub fn blob_session_list(&self, db: &str) -> DbResult<Vec<SessionManifest>> {
        let h = self.get(db)?;
        let q = h.query(
            &format!(
                "SELECT {SESSION_COLS} FROM {BLOB_SESSION_TABLE} ORDER BY created_at, session_id"
            ),
            &[],
        )?;
        Ok(q.rows.iter().map(|r| row_to_session(&q.columns, r)).collect())
    }
}

/// Write-Senke, die nur hasht (keine Datenhaltung im RAM).
struct HashSink(Sha256);

impl Write for HashSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
