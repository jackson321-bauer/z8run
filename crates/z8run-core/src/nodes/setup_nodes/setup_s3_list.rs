//! Setup-Node: s3-list (Bucket/Prefix auflisten via kv-store).

use serde_json::{json, Value};

use super::setup_io::{body, text, S3Cfg};
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
        let ov = req.get("s3").unwrap_or(req);
        let mut cfg = match cfg.mit_override(ov) {
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
        let mut out = body(&msg.payload).clone();
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
