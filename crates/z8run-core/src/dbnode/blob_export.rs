//! EXPORT = PQC-CONTAINER (Jason 30.10.): eine Datei {manifest.json +
//! verschlüsselte Chunks} — funktional wie eine PQC-Zip. Jeder Export bekommt
//! einen EIGENEN Content-Key (nie der DB-Master). Empfänger-Boxen: v3-hybrid.

use crate::dbnode::blob_export_key::{open_container_key, seal_container_key, BoxMode, OpenBox};
use crate::dbnode::blob_io::{decrypt_part, encrypt_part};
use crate::dbnode::blob_meta::load_meta;
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::DbNode;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

const CONTAINER_CHUNK: usize = 256 * 1024;
pub const CONTAINER_FORMAT: &str = "z8-pqc-container/1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerChunk {
    pub i: u64,
    pub ct: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerManifest {
    pub blob_id: String,
    pub name: String,
    pub mime: String,
    pub groesse: u64,
    pub sha256: String,
    pub chunks: Vec<ContainerChunk>,
}

fn err_from(e: String) -> DbError {
    match e.split_once(": ") {
        Some((code, msg)) => DbError::new(code, msg),
        None => DbError::new("BLOB_EXPORT", e),
    }
}

impl DbNode {
    pub async fn blob_export_container(
        &self, db: &str, blob_id: &str, mode: BoxMode<'_>,
    ) -> DbResult<Vec<u8>> {
        let h = self.get(db)?;
        let meta = load_meta(&h, blob_id)?;
        // Inhalt entschlüsseln, mit FRISCHEM Container-Key neu verschlüsseln.
        let plain = self.blob_get_bytes(db, blob_id).await?;
        let ck: [u8; 32] = rand::random();
        let aad_ctx = format!("container:{blob_id}");
        let mut chunks = Vec::new();
        let teile: Vec<&[u8]> = if plain.is_empty() {
            vec![&plain[..]]
        } else {
            plain.chunks(CONTAINER_CHUNK).collect()
        };
        for (i, teil) in teile.iter().enumerate() {
            let ct = encrypt_part(&ck, &aad_ctx, i as u64, teil)?;
            chunks.push(ContainerChunk { i: i as u64, ct: B64.encode(ct) });
        }
        let key_box = seal_container_key(mode, &ck, &format!("z8-container|{blob_id}"))
            .map_err(err_from)?;
        let container = json!({
            "format": CONTAINER_FORMAT,
            "manifest": ContainerManifest {
                blob_id: meta.blob_id,
                name: meta.name,
                mime: meta.mime,
                groesse: meta.groesse,
                sha256: meta.sha256_klartext,
                chunks,
            },
            "key_box": key_box,
        });
        serde_json::to_vec(&container).map_err(|e| DbError::new("JSON", e.to_string()))
    }

    pub fn blob_open_container(container: &[u8], mode: OpenBox<'_>) -> DbResult<Vec<u8>> {
        let v: serde_json::Value =
            serde_json::from_slice(container).map_err(|e| DbError::new("JSON", e.to_string()))?;
        if v["format"].as_str() != Some(CONTAINER_FORMAT) {
            return Err(DbError::new("BLOB_CONTAINER", "unbekanntes Container-Format"));
        }
        let manifest: ContainerManifest = serde_json::from_value(v["manifest"].clone())
            .map_err(|e| DbError::new("BLOB_CONTAINER", format!("manifest: {e}")))?;
        let ck = open_container_key(&v["key_box"], mode).map_err(err_from)?;
        let aad_ctx = format!("container:{}", manifest.blob_id);
        let mut chunks = manifest.chunks.clone();
        chunks.sort_by_key(|c| c.i);
        let mut out = Vec::with_capacity(manifest.groesse as usize);
        for (pos, c) in chunks.iter().enumerate() {
            if c.i != pos as u64 {
                return Err(DbError::new("BLOB_CONTAINER", "Chunk-Reihenfolge/lücke manipuliert"));
            }
            let sealed = B64
                .decode(&c.ct)
                .map_err(|e| DbError::new("BLOB_CONTAINER", format!("Chunk Base64: {e}")))?;
            out.extend_from_slice(&decrypt_part(&ck, &aad_ctx, c.i, &sealed)?);
        }
        if out.len() as u64 != manifest.groesse
            || hex::encode(Sha256::digest(&out)) != manifest.sha256
        {
            return Err(DbError::new("BLOB_INTEGRITY", "Container-SHA256/Größe stimmt nicht"));
        }
        Ok(out)
    }
}
