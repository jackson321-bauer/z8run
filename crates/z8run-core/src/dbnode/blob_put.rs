//! BLOB-PUT mit Content-Dedup: hash STREAMEND ueber eine Temp-Datei (RSS
//! flach), Treffer = kein Upload, nur Metazeile + refcount+1.

use super::blob_io::{blob_prefix, seal_db_key, upload_parts, BLOB_PART_SIZE};
use super::blob_meta::{insert_meta, BlobMeta, BLOB_META_TABLE};
use super::types::{DbError, DbResult};
use super::DbNode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

fn hash_to_temp<R: Read>(reader: &mut R, pfad: &std::path::Path) -> DbResult<(String, u64)> {
    let mut f = std::fs::File::create(pfad)
        .map_err(|e| DbError::new("BLOB_INPUT", format!("temp: {e}")))?;
    let mut buf = vec![0u8; BLOB_PART_SIZE];
    let mut sha = Sha256::new();
    let mut size = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| DbError::new("BLOB_INPUT", format!("lesen: {e}")))?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        f.write_all(&buf[..n])
            .map_err(|e| DbError::new("BLOB_INPUT", format!("temp schreiben: {e}")))?;
        size += n as u64;
    }
    f.flush().map_err(|e| DbError::new("BLOB_INPUT", e.to_string()))?;
    Ok((hex::encode(sha.finalize()), size))
}

async fn donor(h: &super::DbHandle, uri: &str) -> DbResult<(String, u64)> {
    let q = h.query(
        &format!("SELECT content_key_huellereferenz, parts FROM {BLOB_META_TABLE} WHERE storage_uri=?1 LIMIT 1"),
        &[json!(uri)],
    )?;
    let row = q.rows.first().ok_or_else(|| {
        DbError::new("BLOB_DEDUP", format!("Dedup-Treffer ohne Metazeile: {uri}"))
    })?;
    let key = row[0].as_str().unwrap_or_default().to_string();
    let parts = row[1].as_u64().unwrap_or(0);
    Ok((key, parts))
}

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
        h.begin_write(session)?;
        h.end_write();
        let tmp_dir = h.base_dir.join("tmp").join("blob-upload");
        std::fs::create_dir_all(&tmp_dir)
            .map_err(|e| DbError::new("BLOB_INPUT", format!("tmp mkdir: {e}")))?;
        let tmp = tmp_dir.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        let (sha, groesse) = hash_to_temp(reader, &tmp)?;
        let ergebnis = self.put_nach_hash(&h, db, session, owner, name, mime, &tmp, &sha, groesse).await;
        let _ = std::fs::remove_file(&tmp);
        ergebnis
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_nach_hash(
        &self, h: &super::DbHandle, db: &str, session: &str, owner: &str, name: &str,
        mime: &str, tmp: &std::path::Path, sha: &str, groesse: u64,
    ) -> DbResult<BlobMeta> {
        // Dedup-Treffer: nur Metazeile (gleiche storage_uri), kein Upload.
        let vorhanden = h.query(
            "SELECT storage_uri FROM linefs_blobhash WHERE sha256=?1",
            &[json!(sha)],
        )?;
        if let Some(row) = vorhanden.rows.first() {
            let uri = row[0].as_str().unwrap_or_default().to_string();
            let (key, parts) = donor(h, &uri).await?;
            let meta = meta_neu(db, &uuid::Uuid::new_v4().to_string(), name, mime, groesse,
                sha, uri.clone(), key, parts, owner, h.status().wal_stand + 1);
            insert_meta(h, session, &meta).await?;
            h.write(session, "UPDATE linefs_blobhash SET refcount=refcount+1 WHERE sha256=?1",
                vec![json!(sha)]).await?;
            return Ok(meta);
        }
        // Miss: aus Temp-Datei hochladen (streamend, feste Parts).
        let blob_id = uuid::Uuid::new_v4().to_string();
        let content_key: [u8; 32] = rand::random();
        let aad = format!("{db}:{blob_id}");
        let mut f = std::fs::File::open(tmp)
            .map_err(|e| DbError::new("BLOB_INPUT", format!("temp lesen: {e}")))?;
        let (parts, groesse2, sha2) = upload_parts(h, &blob_id, &content_key, &aad, &mut f).await?;
        let key = seal_db_key(h, &blob_id, &content_key)?;
        let uri = format!("{}{}", blob_prefix(db), blob_id);
        let meta = meta_neu(db, &blob_id, name, mime, groesse2, &sha2, uri.clone(), key.clone(),
            parts, owner, h.status().wal_stand + 1);
        insert_meta(h, session, &meta).await?;
        let ins = h.write(session,
            "INSERT INTO linefs_blobhash (sha256,storage_uri,refcount,groesse) VALUES (?1,?2,1,?3)",
            vec![json!(sha2), json!(uri), json!(groesse)]).await;
        match ins {
            Ok(_) => Ok(meta),
            Err(e) if e.message.contains("UNIQUE") => {
                // Race verloren: eigene Metazeile auf Gewinner umbiegen,
                // refcount+1; eigene Parts bleiben Orphan (GC raeumt).
                let q = h.query("SELECT storage_uri FROM linefs_blobhash WHERE sha256=?1",
                    &[json!(sha2)])?;
                let gewinner = q.rows.first().and_then(|r| r[0].as_str()).unwrap_or_default().to_string();
                let (gkey, gparts) = donor(h, &gewinner).await?;
                h.write(session, &format!(
                    "UPDATE {BLOB_META_TABLE} SET storage_uri=?1, content_key_huellereferenz=?2, parts=?3 WHERE blob_id=?4"),
                    vec![json!(gewinner), json!(gkey), json!(gparts), json!(blob_id)]).await?;
                h.write(session, "UPDATE linefs_blobhash SET refcount=refcount+1 WHERE sha256=?1",
                    vec![json!(sha2)]).await?;
                let mut m = meta;
                m.storage_uri = gewinner;
                m.parts = gparts;
                Ok(m)
            }
            Err(e) => Err(e),
        }
    }
}

fn meta_neu(
    db: &str, blob_id: &str, name: &str, mime: &str, groesse: u64, sha: &str, uri: String,
    key: String, parts: u64, owner: &str, epoch: u64,
) -> BlobMeta {
    let _ = db;
    BlobMeta {
        blob_id: blob_id.to_string(),
        name: name.to_string(),
        mime: mime.to_string(),
        groesse,
        sha256_klartext: sha.to_string(),
        content_key_huellereferenz: key,
        storage_uri: uri,
        epoch,
        owner: owner.to_string(),
        parts,
        session_id: None,
        chunk_index: None,
        dauer_ms: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}
