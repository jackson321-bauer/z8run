//! Gemeinsame Helfer der dünnen Z8-DB-Nodes: globale Engine, Cluster-Spec,
//! Payload-Pfade und Output-Form. KEIN SQL-Handling hier.

use crate::dbnode::types::{Adapter, ClusterConfig, DbNodeConfig};
use crate::dbnode::DbNode;
use crate::message::FlowMessage;
use serde_json::{json, Value};
use std::sync::OnceLock;

/// EIN DB-Node pro Prozess (verwaltet alle DBs/Cluster, FEST 4).
pub fn engine() -> &'static DbNode {
    static E: OnceLock<DbNode> = OnceLock::new();
    E.get_or_init(|| DbNode::new(DbNodeConfig::default()))
}

#[derive(Clone, Default)]
pub struct ClusterSpec {
    pub cluster_id: String,
    pub adapter: String,
    pub local_dir: String,
    pub storage_root: String,
    pub bucket: String,
    pub prefix: String,
    pub s3_host: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
}

impl ClusterSpec {
    pub fn from_config(cfg: &Value) -> Self {
        let s = |k: &str, d: &str| {
            cfg.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or(d)
                .to_string()
        };
        Self {
            cluster_id: s("clusterId", "default"),
            adapter: s("adapter", "fs").to_lowercase(),
            local_dir: s("localDir", "/data/z8run/dbnode"),
            storage_root: s("storageRoot", ""),
            bucket: s("bucket", ""),
            prefix: s("prefix", ""),
            s3_host: s("s3Host", ""),
            s3_region: s("s3Region", "us-east-1"),
            s3_access_key: s("s3AccessKey", ""),
            s3_secret_key: s("s3SecretKey", ""),
        }
    }

    pub fn to_cluster(&self) -> ClusterConfig {
        let local = std::path::PathBuf::from(&self.local_dir);
        let adapter = if self.adapter == "s3" {
            Adapter::S3 {
                host: self.s3_host.clone(),
                region: self.s3_region.clone(),
                access_key: self.s3_access_key.clone(),
                secret_key: self.s3_secret_key.clone(),
                bucket: self.bucket.clone(),
                prefix: self.prefix.clone(),
            }
        } else {
            let root = if self.storage_root.is_empty() {
                local.join("storage")
            } else {
                std::path::PathBuf::from(&self.storage_root)
            };
            Adapter::Fs {
                root: root.to_string_lossy().to_string(),
            }
        };
        ClusterConfig {
            cluster_id: self.cluster_id.clone(),
            local_dir: local,
            adapter,
        }
    }
}

/// Liest einen Punkt-Pfad ("req.body.x") aus dem Payload.
pub fn at<'a>(payload: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(payload);
    }
    let mut cur = payload;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

pub fn at_str(payload: &Value, path: &str, default: &str) -> String {
    at(payload, path)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

pub fn at_params(payload: &Value, path: &str) -> Vec<Value> {
    at(payload, path)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Masterkey aus dem Payload (Login/Proxy-Scope): Base64 oder Hex.
pub fn master_at(payload: &Value, path: &str) -> Result<Vec<u8>, String> {
    let raw = at(payload, path)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Masterkey fehlt ({path})"))?;
    use base64::Engine;
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(raw) {
        return Ok(v);
    }
    let hexs = raw.strip_prefix("0x").unwrap_or(raw);
    hex::decode(hexs).map_err(|e| format!("Masterkey weder Base64 noch Hex: {e}"))
}

pub fn ok(msg: &FlowMessage, payload: Value) -> Vec<FlowMessage> {
    vec![msg.derive(msg.source_node, "output", payload)]
}

pub fn err(msg: &FlowMessage, code: &str, message: &str) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({"status": 400, "code": code, "error": message}),
    )]
}
