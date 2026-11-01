//! S3-/Payload-Verkabelung der Setup-Nodes. S3 läuft ausschließlich über
//! `kv-store` (SigV4) — kein aws-cli, kein zweiter HTTP-Client. Einzel- und
//! Provider-Set-Config (Mehrfach-Quorum) teilen sich DIESELBE S3Cfg.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kv_store::s3::S3Endpoint;
use serde_json::Value;

use super::setup_multi::{self, Multi, WriteInfo};
use super::setup_quorum as q;

#[derive(Clone)]
pub struct S3Cfg {
    pub endpoint: S3Endpoint,
    pub bucket: String,
    pub prefix: String,
    pub multi: Option<Multi>,
}

impl S3Cfg {
    pub fn aus_datei(path: &str) -> Result<Self, String> {
        Self::aus_datei_mit(path, None, None)
    }

    /// Liest Einzel- ODER Provider-Set-Config (Keys nur in der Config).
    pub fn aus_datei_mit(
        path: &str,
        bucket: Option<&str>,
        prefix: Option<&str>,
    ) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("s3 config {path}: {e}"))?;
        let cfg: Value = serde_json::from_str(&raw).map_err(|e| format!("s3 parse: {e}"))?;
        let p = setup_multi::parse(&cfg, bucket, prefix)?;
        Ok(Self {
            endpoint: p.endpoint,
            bucket: p.bucket,
            prefix: p.prefix,
            multi: p.multi,
        })
    }

    pub fn mit_override(&self, ov: &Value) -> Result<Self, String> {
        let mut out = self.clone();
        if let Some(v) = ov.get("bucket").and_then(|v| v.as_str()) {
            out.bucket = v.to_string();
        }
        if let Some(v) = ov.get("prefix").and_then(|v| v.as_str()) {
            out.prefix = v.to_string();
        }
        if let Some(v) = ov.get("host").and_then(|v| v.as_str()) {
            out.endpoint.host = v.to_string();
        }
        if let Some(v) = ov.get("region").and_then(|v| v.as_str()) {
            out.endpoint.region = v.to_string();
        }
        if let Some(v) = ov.get("access_key").and_then(|v| v.as_str()) {
            out.endpoint.access_key = v.to_string();
        }
        if let Some(v) = ov.get("secret_key").and_then(|v| v.as_str()) {
            out.endpoint.secret_key = v.to_string();
        }
        if out.bucket.is_empty() {
            return Err("S3 bucket fehlt".into());
        }
        Ok(out)
    }

    pub fn key(&self, name: &str) -> String {
        let name = name.trim_start_matches('/');
        format!("{}{name}", self.prefix)
    }

    pub fn targets(&self) -> Vec<q::Target> {
        match &self.multi {
            Some(m) => m
                .targets
                .iter()
                .map(|t| (t.label.clone(), t.endpoint.clone(), t.bucket.clone()))
                .collect(),
            None => vec![("default".into(), self.endpoint.clone(), self.bucket.clone())],
        }
    }

    pub fn quorum_min(&self) -> usize {
        self.multi.as_ref().map(|m| m.quorum_min).unwrap_or(1)
    }

    pub async fn health(&self) -> Vec<(String, bool)> {
        q::health(&self.targets()).await
    }

    pub async fn ensure_quorum(&self) -> Result<Vec<(String, bool)>, String> {
        let h = self.health().await;
        let ok = h.iter().filter(|(_, v)| *v).count();
        if ok < self.quorum_min() {
            return Err(format!(
                "Zwangsquorum verfehlt: {ok}/{} erreichbar, min {} — fail-closed",
                h.len(),
                self.quorum_min()
            ));
        }
        Ok(h)
    }

    pub async fn put_quorum(&self, name: &str, data: Vec<u8>) -> Result<WriteInfo, String> {
        q::put(&self.targets(), &self.key(name), data, self.quorum_min()).await
    }

    pub async fn put(&self, name: &str, data: Vec<u8>) -> Result<String, String> {
        Ok(self.put_quorum(name, data).await?.key)
    }

    pub async fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        q::get(&self.targets(), &self.key(name)).await
    }

    pub async fn exists(&self, name: &str) -> bool {
        self.get(name).await.is_ok()
    }

    pub async fn list(&self, name_prefix: &str) -> Result<Vec<(String, u64)>, String> {
        q::list(&self.targets(), &self.key(name_prefix)).await
    }

    pub async fn delete(&self, name: &str) -> Result<(), String> {
        q::delete(&self.targets(), &self.key(name)).await
    }

    pub async fn create_buckets(&self) -> Result<Vec<(String, String)>, String> {
        q::create_buckets(&self.targets()).await
    }

    pub async fn replicas_eq(&self, name: &str) -> Result<Vec<(String, String)>, String> {
        q::replicas_eq(&self.targets(), &self.key(name)).await
    }
}

/// Request-Body: `{req:{body:{...}}}` oder direktes Objekt.
pub fn body(payload: &Value) -> &Value {
    payload
        .get("req")
        .and_then(|r| r.get("body"))
        .unwrap_or(payload)
}

/// Dot-Pfad-Lookup mit Array-Indizes (`users.0.name`).
pub fn pfad<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(value);
    }
    let mut cur = value;
    for part in path.split('.') {
        cur = match cur {
            Value::Object(map) => map.get(part)?,
            Value::Array(arr) => arr.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

pub fn text<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    pfad(value, path).and_then(|v| v.as_str())
}

pub fn datei_eintrag(name: String, data: Vec<u8>, encoding: &str) -> Value {
    if encoding == "utf8" {
        serde_json::json!({
            "key": name,
            "encoding": "utf8",
            "text": String::from_utf8_lossy(&data),
            "sha256": super::setup_crypto::sha_hex(&data),
            "bytes": data.len(),
        })
    } else {
        serde_json::json!({
            "key": name,
            "encoding": "base64",
            "content_b64": B64.encode(&data),
            "sha256": super::setup_crypto::sha_hex(&data),
            "bytes": data.len(),
        })
    }
}

pub fn datei_bytes(entry: &Value) -> Result<Vec<u8>, String> {
    if let Some(t) = entry.get("text").and_then(|v| v.as_str()) {
        return Ok(t.as_bytes().to_vec());
    }
    if let Some(b) = entry.get("content_b64").and_then(|v| v.as_str()) {
        return B64.decode(b).map_err(|e| format!("content_b64: {e}"));
    }
    Err("Datei-Eintrag ohne text/content_b64".into())
}

/// Einheitlicher Fehlerausgang der Setup-Nodes.
pub fn fehler(msg: &crate::message::FlowMessage, text: impl Into<String>) -> Vec<crate::message::FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        serde_json::json!({ "status": 400, "error": text.into() }),
    )]
}
