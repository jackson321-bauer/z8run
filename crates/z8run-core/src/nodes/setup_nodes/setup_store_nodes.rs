//! Setup-Nodes: s3-put, s3-list (kv-store/SigV4).

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, datei_bytes, pfad, S3Cfg};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
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
        tracing::info!(node="s3-put", keys=?req.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()), "setup node start");
        let cfg = match S3Cfg::aus_datei(&self.s3_config) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, &format!("s3-put: {e}"))),
        };
        let ov = req.get("s3").unwrap_or(req);
        let mut cfg = match cfg.mit_override(ov) {
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
        let mut out = body(&msg.payload).clone();
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
