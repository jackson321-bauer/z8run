//! Setup-Node: hashdatei-write (Argon2IDHashDatei/3).

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, datei_eintrag, pfad, text};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
use crate::message::FlowMessage;
use crate::node_factory;

fn fehler(msg: &FlowMessage, text: &str) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": 400, "error": text }),
    )]
}

// hashdatei-write
// ---------------------------------------------------------------------------

pub struct HashdateiWriteNode {
    name: String,
    entries_path: String,
    out_path: String,
    key: String,
    key_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for HashdateiWriteNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let entries = pfad(req, &self.entries_path)
            .and_then(|v| v.as_array())
            .cloned()
            .or_else(|| {
                let mut all = Vec::new();
                if let Some(one) = req.get("secretbox") {
                    all.push(one.clone());
                }
                if let Some(many) = req.get("secretboxes").and_then(|v| v.as_array()) {
                    all.extend(many.iter().cloned());
                }
                if all.is_empty() {
                    None
                } else {
                    Some(all)
                }
            })
            .unwrap_or_default();
        if entries.is_empty() {
            return Ok(fehler(&msg, "hashdatei-write: keine secretboxes"));
        }
        let mut addrs = Vec::new();
        let mut chiffren = Vec::new();
        for e in &entries {
            let Some(addr) = e["addr"].as_str() else {
                return Ok(fehler(&msg, "hashdatei-write: addr fehlt"));
            };
            let Some(block) = e["block"].as_str() else {
                return Ok(fehler(&msg, "hashdatei-write: block fehlt"));
            };
            let Some(box_b64) = e["box_b64"].as_str() else {
                return Ok(fehler(&msg, "hashdatei-write: box_b64 fehlt"));
            };
            addrs.push((addr.to_string(), block.to_string()));
            chiffren.push((block.to_string(), box_b64.to_string()));
        }
        let text_out = sc::hashdatei_bauen(&addrs, &chiffren);
        let sha = sc::sha_hex(text_out.as_bytes());
        let key = if !self.key.is_empty() {
            self.key.clone()
        } else {
            text(req, &self.key_path).unwrap_or_default().to_string()
        };
        let out_path = if !self.out_path.is_empty() {
            self.out_path.clone()
        } else {
            text(req, "outPath").unwrap_or_default().to_string()
        };
        if !out_path.is_empty() {
            if let Some(parent) = std::path::Path::new(&out_path).parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Z8Error::Internal(format!("hashdatei-write dir {out_path}: {e}"))
                })?;
            }
            std::fs::write(&out_path, &text_out)
                .map_err(|e| Z8Error::Internal(format!("hashdatei-write {out_path}: {e}")))?;
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("hashdatei".into(), json!(text_out));
            o.insert("hashdatei_sha256".into(), json!(sha));
            o.insert("hashdatei_key".into(), json!(key));
            let entry = datei_eintrag(key, text_out.into_bytes(), "utf8");
            let files = o
                .entry("files")
                .or_insert_with(|| json!([]))
                .as_array_mut();
            if let Some(files) = files {
                files.push(entry);
            }
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "entriesPath" => entries_path: str,
            "outPath" => out_path: str,
            "key" => key: str,
            "keyPath" => key_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "hashdatei-write"
    }
}

node_factory!(HashdateiWriteNodeFactory, HashdateiWriteNode, "hashdatei-write", {
    name: "hashdatei-write".to_string(),
    entries_path: "secretboxes".to_string(),
    out_path: String::new(),
    key: String::new(),
    key_path: "hashdatei_key".to_string(),
});

