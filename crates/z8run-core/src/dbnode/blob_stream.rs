//! CHUNK-STREAMING (HLS-Muster): Zeit-Chunks je Aufnahme = eigene unveränder-
//! liche Blobs, EIN Session-Content-Key, Chunk-Keys per HKDF(Session-Key, i).
//! MANIFEST-ZEILE in der DB ist die Playlist (Reihenfolge + gesamt-sha256).

use crate::dbnode::blob_io::{derive, open_db_key, seal_db_key, upload_parts};
use crate::dbnode::blob_meta::{insert_meta, BlobMeta, BLOB_SESSION_TABLE};
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::{DbHandle, DbNode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const SESSION_COLS: &str = "session_id,owner,mime,chunk_ids,gesamt_sha256,\
dauer_ms,session_key_huellereferenz,epoch,created_at";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionManifest {
    pub session_id: String,
    pub owner: String,
    pub mime: String,
    pub chunk_ids: Vec<String>,
    pub gesamt_sha256: String,
    pub dauer_ms: u64,
    /// NUR Engine-intern: versiegelter Session-Key. Wird NIE serialisiert.
    #[serde(skip_serializing, default)]
    pub session_key_huellereferenz: String,
    pub epoch: u64,
    pub created_at: String,
}

pub(crate) fn row_to_session(cols: &[String], row: &[Value]) -> SessionManifest {
    let get = |n: &str| -> Value {
        cols.iter()
            .position(|c| c == n)
            .and_then(|i| row.get(i).cloned())
            .unwrap_or(Value::Null)
    };
    let ids: Vec<String> = get("chunk_ids")
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    SessionManifest {
        session_id: get("session_id").as_str().unwrap_or_default().to_string(),
        owner: get("owner").as_str().unwrap_or_default().to_string(),
        mime: get("mime").as_str().unwrap_or_default().to_string(),
        chunk_ids: ids,
        gesamt_sha256: get("gesamt_sha256").as_str().unwrap_or_default().to_string(),
        dauer_ms: get("dauer_ms").as_u64().unwrap_or(0),
        session_key_huellereferenz: get("session_key_huellereferenz")
            .as_str()
            .unwrap_or_default()
            .to_string(),
        epoch: get("epoch").as_u64().unwrap_or(0),
        created_at: get("created_at").as_str().unwrap_or_default().to_string(),
    }
}

pub(crate) fn load_session(h: &DbHandle, sid: &str) -> DbResult<SessionManifest> {
    let q = h.query(
        &format!("SELECT {SESSION_COLS} FROM {BLOB_SESSION_TABLE} WHERE session_id = ?1"),
        &[json!(sid)],
    )?;
    q.rows
        .first()
        .map(|r| row_to_session(&q.columns, r))
        .ok_or_else(|| DbError::new("BLOB_SESSION", format!("Session {sid} unbekannt")))
}

pub(crate) fn session_content_key(h: &DbHandle, sid: &str) -> DbResult<[u8; 32]> {
    let m = load_session(h, sid)?;
    open_db_key(h, sid, &m.session_key_huellereferenz)
}

pub(crate) fn chunk_keys(sk: &[u8; 32], sid: &str, idx: u64) -> ([u8; 32], String) {
    let info = format!("chunk:{sid}:{idx}");
    (derive(sk, info.as_bytes()), info)
}

impl DbNode {
    pub async fn blob_session_begin(
        &self, db: &str, session: &str, owner: &str, mime: &str,
    ) -> DbResult<SessionManifest> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let sid = uuid::Uuid::new_v4().to_string();
        let sk: [u8; 32] = rand::random();
        let m = SessionManifest {
            session_id: sid.clone(),
            owner: owner.to_string(),
            mime: mime.to_string(),
            chunk_ids: Vec::new(),
            gesamt_sha256: String::new(),
            dauer_ms: 0,
            session_key_huellereferenz: seal_db_key(&h, &sid, &sk)?,
            epoch: h.status().wal_stand + 1,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let sql = format!(
            "INSERT INTO {BLOB_SESSION_TABLE} ({SESSION_COLS}) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"
        );
        let params = vec![
            json!(m.session_id), json!(m.owner), json!(m.mime),
            json!(serde_json::to_string(&m.chunk_ids)?), json!(m.gesamt_sha256),
            json!(m.dauer_ms), json!(m.session_key_huellereferenz),
            json!(m.epoch), json!(m.created_at),
        ];
        h.write(session, &sql, params).await?;
        Ok(m)
    }

    /// Ein Zeit-Chunk: sofort verschlüsselt hochgeladen, eigene Meta-Zeile,
    /// KEINE eigene Key-Hülle (Key = HKDF(Session-Key, chunk_index)).
    pub async fn blob_session_append(
        &self, db: &str, session: &str, sid: &str, data: &[u8], dauer_ms: u64,
    ) -> DbResult<BlobMeta> {
        let h = self.get(db)?;
        h.begin_write(session)?;
        h.end_write();
        let m = load_session(&h, sid)?;
        let idx = m.chunk_ids.len() as u64;
        let sk = session_content_key(&h, sid)?;
        let (chunk_key, aad_ctx) = chunk_keys(&sk, sid, idx);
        let blob_id = uuid::Uuid::new_v4().to_string();
        let mut cur = std::io::Cursor::new(data);
        let (parts, groesse, sha) =
            upload_parts(&h, &blob_id, &chunk_key, &aad_ctx, &mut cur).await?;
        let meta = BlobMeta {
            blob_id: blob_id.clone(),
            name: format!("{sid}-{idx:04}"),
            mime: m.mime.clone(),
            groesse,
            sha256_klartext: sha,
            content_key_huellereferenz: String::new(),
            storage_uri: format!("blobs/{db}/{blob_id}"),
            epoch: h.status().wal_stand + 1,
            owner: m.owner.clone(),
            parts,
            session_id: Some(sid.to_string()),
            chunk_index: Some(idx),
            dauer_ms: Some(dauer_ms),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        insert_meta(&h, session, &meta).await?;
        let mut ids = m.chunk_ids.clone();
        ids.push(blob_id);
        h.write(
            session,
            &format!(
                "UPDATE {BLOB_SESSION_TABLE} SET chunk_ids = ?1, dauer_ms = ?2 \
                 WHERE session_id = ?3"
            ),
            vec![json!(serde_json::to_string(&ids)?), json!(m.dauer_ms + dauer_ms), json!(sid)],
        )
        .await?;
        Ok(meta)
    }
}
