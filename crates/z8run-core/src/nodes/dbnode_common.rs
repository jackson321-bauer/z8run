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
        let cluster_ref = s("clusterRef", "");
        let cluster_id = if cluster_ref.is_empty() {
            s("clusterId", "default")
        } else {
            cluster_ref
        };
        Self {
            cluster_id,
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
    let t = raw.trim();
    let hexs = t.strip_prefix("0x").unwrap_or(t);
    // Hex (32-Byte-Key) zuerst; 64 Hex-Stellen sind auch Base64-Alphabet.
    if hexs.len() == 64 && hexs.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v) = hex::decode(hexs) {
            return Ok(v);
        }
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| format!("Masterkey weder Base64 noch Hex: {e}"))
}

/// Entfernt bekannte Masterkey-Pfade aus jedem Node-Output.
fn strip_known_secrets(v: &mut Value) {
    for p in [
        "master_key_b64",
        "req.body.master_key_b64",
        "master",
        "req.body.master",
    ] {
        strip_path(v, p);
    }
}

/// Merge: Eingabe-Payload bleibt erhalten, Node-Felder werden flach ergänzt.
pub fn merge(base: &Value, extra: Value) -> Value {
    let mut out = match base {
        Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };
    if let Value::Object(extra) = extra {
        for (k, v) in extra {
            out.insert(k, v);
        }
    }
    Value::Object(out)
}

pub fn ok(msg: &FlowMessage, payload: Value) -> Vec<FlowMessage> {
    let mut base = msg.payload.clone();
    strip_known_secrets(&mut base);
    let merged = merge(&base, payload);
    vec![msg.derive(msg.source_node, "output", merged)]
}
/// Entfernt einen Punkt-Pfad (z. B. den Masterkey) aus dem Payload.
pub fn strip_path(v: &mut Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return;
    }
    let mut cur = v;
    for part in &parts[..parts.len() - 1] {
        match cur.get_mut(*part) {
            Some(next) => cur = next,
            None => return,
        }
    }
    if let Some(obj) = cur.as_object_mut() {
        obj.remove(parts[parts.len() - 1]);
    }
}
pub fn ok_without(msg: &FlowMessage, payload: Value, strip: &str) -> Vec<FlowMessage> {
    let mut base = msg.payload.clone();
    strip_known_secrets(&mut base);
    strip_path(&mut base, strip);
    let merged = merge(&base, payload);
    vec![msg.derive(msg.source_node, "output", merged)]
}
pub fn err_without(msg: &FlowMessage, code: &str, message: &str, strip: &str) -> Vec<FlowMessage> {
    let mut base = msg.payload.clone();
    strip_known_secrets(&mut base);
    strip_path(&mut base, strip);
    let merged = merge(
        &base,
        json!({"status": 400, "code": code, "error": message}),
    );
    vec![msg.derive(msg.source_node, "error", merged)]
}
pub fn err(msg: &FlowMessage, code: &str, message: &str) -> Vec<FlowMessage> {
    let mut base = msg.payload.clone();
    strip_known_secrets(&mut base);
    let merged = merge(
        &base,
        json!({"status": 400, "code": code, "error": message}),
    );
    vec![msg.derive(msg.source_node, "error", merged)]
}
