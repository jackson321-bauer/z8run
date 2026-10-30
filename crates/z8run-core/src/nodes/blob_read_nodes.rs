//! `blob-get` und `blob-list`: dünn, Engine dahinter, Kategorie data.
//! get liefert Klartext NUR an den authentisierten Aufrufer (Flow-Payload
//! oder Datei-Ziel im Adapter-Pfad) — nie als öffentliche URL.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at_str, engine, err, ok};
use base64::Engine;
use serde_json::{json, Value};

pub struct BlobGetNode {
    name: String,
    db_id: String,
    blob_id_path: String,
    ziel_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for BlobGetNode {
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
        let ziel = at_str(&msg.payload, &self.ziel_path, "");
        let node = engine();
        if !ziel.is_empty() {
            match node
                .blob_get_to_file(&db, &blob_id, std::path::Path::new(&ziel))
                .await
            {
                Ok(meta) => return Ok(ok(&msg, json!({"status": 200, "db": db,
                                                       "ziel": ziel, "blob": meta}))),
                Err(e) => return Ok(err(&msg, &e.code, &e.message)),
            }
        }
        match node.blob_get_bytes(&db, &blob_id).await {
            Ok(data) => Ok(ok(&msg, json!({
                "status": 200, "db": db, "blob_id": blob_id,
                "groesse": data.len(),
                "base64": base64::engine::general_purpose::STANDARD.encode(&data),
            }))),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "dbId" => db_id: str,
            "blobIdPath" => blob_id_path: str,
            "zielPath" => ziel_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "blob-get"
    }
}

node_factory!(BlobGetNodeFactory, BlobGetNode, "blob-get", {
    name: String::new(),
    db_id: String::new(),
    blob_id_path: "blob_id".to_string(),
    ziel_path: "ziel_adapter".to_string()
});

pub struct BlobListNode {
    name: String,
    db_id: String,
}

#[async_trait::async_trait]
impl NodeExecutor for BlobListNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        match engine().blob_list(&db) {
            Ok(blobs) => {
                let ui: Vec<Value> = blobs
                    .iter()
                    .map(|b| json!({
                        "blob_id": b.blob_id, "name": b.name, "mime": b.mime,
                        "groesse": b.groesse, "epoch": b.epoch,
                        "owner": b.owner, "parts": b.parts,
                    }))
                    .collect();
                Ok(ok(&msg, json!({"status": 200, "db": db, "blobs": ui})))
            }
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "blob-list"
    }
}

node_factory!(BlobListNodeFactory, BlobListNode, "blob-list", {
    name: String::new(),
    db_id: String::new()
});
