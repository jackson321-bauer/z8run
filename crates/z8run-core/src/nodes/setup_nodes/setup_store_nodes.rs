//! Setup-Nodes S1/S2: hashdatei-write, s3-put, s3-list.

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, datei_bytes, datei_eintrag, pfad, text, S3Cfg};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;

fn fehler(msg: &FlowMessage, text: &str) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": 400, "error": text }),
    )]
}

// ---------------------------------------------------------------------------
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
        let mut out = msg.payload.clone();
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

// ---------------------------------------------------------------------------
// s3-put
// ---------------------------------------------------------------------------

pub struct S3PutNode {
    name: String,
    s3_config: String,
    bucket: String,
    prefix: String,
    files_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for S3PutNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let cfg = match S3Cfg::aus_datei(&self.s3_config) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, &format!("s3-put: {e}"))),
        };
        let mut cfg = match cfg.mit_override(req) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, &format!("s3-put: {e}"))),
        };
        if !self.bucket.is_empty() {
            cfg.bucket = self.bucket.clone();
        }
        if !self.prefix.is_empty() {
            cfg.prefix = self.prefix.clone();
        }
        let files = pfad(req, &self.files_path)
            .and_then(|v| v.as_array())
            .cloned()
            .or_else(|| {
                req.get("files")
                    .and_then(|v| v.as_array())
                    .cloned()
            })
            .unwrap_or_default();
        let mut single = None;
        if files.is_empty() {
            if let (Some(key), Some(data)) = (
                req.get("key").and_then(|v| v.as_str()),
                req.get("text").or_else(|| req.get("content_b64")),
            ) {
                let mut entry = json!({ "key": key });
                if data.is_string() && req.get("content_b64").is_some() {
                    entry["content_b64"] = data.clone();
                } else {
                    entry["text"] = data.clone();
                }
                single = Some(entry);
            }
        }
        let liste: Vec<Value> = if let Some(e) = single { vec![e] } else { files };
        if liste.is_empty() {
            return Ok(fehler(&msg, "s3-put: keine files"));
        }
        let mut results = Vec::new();
        for entry in &liste {
            let Some(key) = entry["key"].as_str() else {
                return Ok(fehler(&msg, "s3-put: key fehlt"));
            };
            let data = match datei_bytes(entry) {
                Ok(d) => d,
                Err(e) => return Ok(fehler(&msg, &format!("s3-put {key}: {e}"))),
            };
            let sha = sc::sha_hex(&data);
            match cfg.put(key, data).await {
                Ok(full) => results.push(json!({
                    "key": key,
                    "bucket": cfg.bucket,
                    "full_key": full,
                    "sha256": sha,
                })),
                Err(e) => return Ok(fehler(&msg, &format!("s3-put: {e}"))),
            }
        }
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("s3_put".into(), json!(results));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "bucket" => bucket: str,
            "prefix" => prefix: str,
            "filesPath" => files_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "s3-put braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "s3-put"
    }
}

node_factory!(S3PutNodeFactory, S3PutNode, "s3-put", {
    name: "s3-put".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    bucket: String::new(),
    prefix: String::new(),
    files_path: "files".to_string(),
});

// ---------------------------------------------------------------------------
// s3-list
// ---------------------------------------------------------------------------

pub struct S3ListNode {
    name: String,
    s3_config: String,
    bucket: String,
    prefix: String,
}

#[async_trait::async_trait]
impl NodeExecutor for S3ListNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let cfg = match S3Cfg::aus_datei(&self.s3_config) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, &format!("s3-list: {e}"))),
        };
        let mut cfg = match cfg.mit_override(req) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, &format!("s3-list: {e}"))),
        };
        if !self.bucket.is_empty() {
            cfg.bucket = self.bucket.clone();
        }
        if !self.prefix.is_empty() {
            cfg.prefix = self.prefix.clone();
        }
        let prefix = text(req, "prefix")
            .map(|s| s.to_string())
            .or_else(|| req.get("list_prefix").and_then(|v| v.as_str()).map(str::to_string))
            .unwrap_or_default();
        let objects = match cfg.list(&prefix).await {
            Ok(o) => o,
            Err(e) => return Ok(fehler(&msg, &format!("s3-list: {e}"))),
        };
        let liste: Vec<Value> = objects
            .into_iter()
            .map(|(key, size)| json!({ "key": key, "size": size }))
            .collect();
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("objects".into(), json!(liste));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "bucket" => bucket: str,
            "prefix" => prefix: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "s3-list braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "s3-list"
    }
}

node_factory!(S3ListNodeFactory, S3ListNode, "s3-list", {
    name: "s3-list".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    bucket: String::new(),
    prefix: String::new(),
});
