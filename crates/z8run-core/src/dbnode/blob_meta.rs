//! Blob-Metadaten = eine Zeile je Blob (linefs-blobs). Rohdaten nie in SQLite.

use crate::dbnode::types::DbResult;
use crate::dbnode::DbHandle;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const BLOB_META_TABLE: &str = "linefs_blobs";
pub const BLOB_SESSION_TABLE: &str = "linefs_blob_sessions";
pub(crate) const META_COLS: &str = "blob_id,name,mime,groesse,sha256_klartext,\
content_key_huellereferenz,storage_uri,epoch,owner,parts,session_id,chunk_index,\
dauer_ms,created_at";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    pub blob_id: String,
    pub name: String,
    pub mime: String,
    pub groesse: u64,
    pub sha256_klartext: String,
    /// NUR Engine-intern: versiegelter Content-Key. Wird NIE serialisiert
    /// (Node-/MCP-/CLI-Antworten und Logs sehen nur die Metadaten).
    #[serde(skip_serializing, default)]
    pub content_key_huellereferenz: String,
    pub storage_uri: String,
    pub epoch: u64,
    pub owner: String,
    pub parts: u64,
    pub session_id: Option<String>,
    pub chunk_index: Option<u64>,
    pub dauer_ms: Option<u64>,
    pub created_at: String,
}

pub(crate) fn row_to_meta(cols: &[String], row: &[Value]) -> BlobMeta {
    let get = |name: &str| -> Value {
        cols.iter()
            .position(|c| c == name)
            .and_then(|i| row.get(i).cloned())
            .unwrap_or(Value::Null)
    };
    BlobMeta {
        blob_id: get("blob_id").as_str().unwrap_or_default().to_string(),
        name: get("name").as_str().unwrap_or_default().to_string(),
        mime: get("mime").as_str().unwrap_or_default().to_string(),
        groesse: get("groesse").as_u64().unwrap_or(0),
        sha256_klartext: get("sha256_klartext").as_str().unwrap_or_default().to_string(),
        content_key_huellereferenz: get("content_key_huellereferenz")
            .as_str()
            .unwrap_or_default()
            .to_string(),
        storage_uri: get("storage_uri").as_str().unwrap_or_default().to_string(),
        epoch: get("epoch").as_u64().unwrap_or(0),
        owner: get("owner").as_str().unwrap_or_default().to_string(),
        parts: get("parts").as_u64().unwrap_or(0),
        session_id: get("session_id").as_str().map(|s| s.to_string()),
        chunk_index: get("chunk_index").as_u64(),
        dauer_ms: get("dauer_ms").as_u64(),
        created_at: get("created_at").as_str().unwrap_or_default().to_string(),
    }
}

pub(crate) fn load_meta(h: &DbHandle, blob_id: &str) -> DbResult<BlobMeta> {
    let q = h.query(
        &format!("SELECT {META_COLS} FROM {BLOB_META_TABLE} WHERE blob_id = ?1"),
        &[json!(blob_id)],
    )?;
    q.rows
        .first()
        .map(|r| row_to_meta(&q.columns, r))
        .ok_or_else(|| crate::dbnode::types::DbError::new(
            "BLOB_NOT_FOUND",
            format!("Blob {blob_id} unbekannt"),
        ))
}

pub(crate) async fn insert_meta(h: &DbHandle, session: &str, m: &BlobMeta) -> DbResult<u64> {
    let sql = format!(
        "INSERT INTO {BLOB_META_TABLE} ({META_COLS}) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)"
    );
    let params = vec![
        json!(m.blob_id), json!(m.name), json!(m.mime), json!(m.groesse),
        json!(m.sha256_klartext), json!(m.content_key_huellereferenz),
        json!(m.storage_uri), json!(m.epoch), json!(m.owner), json!(m.parts),
        json!(m.session_id), json!(m.chunk_index), json!(m.dauer_ms),
        json!(m.created_at),
    ];
    Ok(h.write(session, &sql, params).await?.wal_nr)
}
