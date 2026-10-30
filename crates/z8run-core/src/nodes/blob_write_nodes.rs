//! `blob-put` und `blob-delete`: dünn, Engine dahinter, Kategorie data.
//! Put: Datei-Pfad ODER base64 (klein); Meta-Zeile via WAL. Delete: erst
//! Meta-Zeile, dann Backend (Ein-Schreiber-Regel gilt auch für Meta-Zeilen).

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at_str, engine, err, ok};
use base64::Engine;
use serde_json::{json, Value};

pub struct BlobPutNode {
    name: String,
    db_id: String,
    name_cfg: String,
    mime_cfg: String,
    pfad_path: String,
    base64_path: String,
    session_path: String,
    auto_reserve: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for BlobPutNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        let name = if self.name_cfg.is_empty() {
            at_str(&msg.payload, "name", "blob.bin")
        } else {
            self.name_cfg.clone()
        };
        let mime = if self.mime_cfg.is_empty() {
            at_str(&msg.payload, "mime", "application/octet-stream")
        } else {
            self.mime_cfg.clone()
        };
        let owner = at_str(&msg.payload, "owner", "blob");
        let session = at_str(&msg.payload, &self.session_path, "blob-session");
        let node = engine();
        if self.auto_reserve {
            if let Err(e) = node.reserve(&db, &session) {
                return Ok(err(&msg, &e.code, &e.message));
            }
        }
        let pfad = at_str(&msg.payload, &self.pfad_path, "");
        let result = if !pfad.is_empty() && std::path::Path::new(&pfad).is_file() {
            node.blob_put_file(&db, &session, &owner, &name, &mime, std::path::Path::new(&pfad))
                .await
        } else {
            let b64 = at_str(&msg.payload, &self.base64_path, "");
            if b64.is_empty() {
                if self.auto_reserve {
                    let _ = node.release(&db, &session);
                }
                return Ok(err(&msg, "BLOB_INPUT", "weder Datei-Pfad noch base64"));
            }
            match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                Ok(data) => node.blob_put_bytes(&db, &session, &owner, &name, &mime, &data).await,
                Err(e) => {
                    if self.auto_reserve {
                        let _ = node.release(&db, &session);
                    }
                    return Ok(err(&msg, "BLOB_INPUT", &format!("base64: {e}")));
                }
            }
        };
        if self.auto_reserve {
            let _ = node.release(&db, &session);
        }
        match result {
            Ok(meta) => Ok(ok(&msg, json!({"status": 200, "db": db, "blob": meta}))),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "dbId" => db_id: str,
            "blobName" => name_cfg: str,
            "mime" => mime_cfg: str,
            "pfadPath" => pfad_path: str,
            "base64Path" => base64_path: str,
            "sessionPath" => session_path: str,
            "autoReserve" => auto_reserve: bool,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "blob-put"
    }
}

node_factory!(BlobPutNodeFactory, BlobPutNode, "blob-put", {
    name: String::new(),
    db_id: String::new(),
    name_cfg: String::new(),
    mime_cfg: String::new(),
    pfad_path: "req.body.datei_pfad".to_string(),
    base64_path: "req.body.base64".to_string(),
    session_path: "session_id".to_string(),
    auto_reserve: true
});

pub struct BlobDeleteNode {
    name: String,
    db_id: String,
    blob_id_path: String,
    session_path: String,
    auto_reserve: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for BlobDeleteNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        let blob_id = at_str(&msg.payload, &self.blob_id_path, "");
        if blob_id.is_empty() {
            return Ok(err(&msg, "BLOB_INPUT", "blob_id fehlt"));
        }
        let session = at_str(&msg.payload, &self.session_path, "blob-session");
        let node = engine();
        if self.auto_reserve {
            if let Err(e) = node.reserve(&db, &session) {
                return Ok(err(&msg, &e.code, &e.message));
            }
        }
        let result = node.blob_delete(&db, &session, &blob_id).await;
        if self.auto_reserve {
            let _ = node.release(&db, &session);
        }
        match result {
            Ok(parts) => Ok(ok(&msg, json!({"status": 200, "db": db,
                                           "blob_id": blob_id, "parts": parts}))),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "dbId" => db_id: str,
            "blobIdPath" => blob_id_path: str,
            "sessionPath" => session_path: str,
            "autoReserve" => auto_reserve: bool,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "blob-delete"
    }
}

node_factory!(BlobDeleteNodeFactory, BlobDeleteNode, "blob-delete", {
    name: String::new(),
    db_id: String::new(),
    blob_id_path: "blob_id".to_string(),
    session_path: "session_id".to_string(),
    auto_reserve: false
});
