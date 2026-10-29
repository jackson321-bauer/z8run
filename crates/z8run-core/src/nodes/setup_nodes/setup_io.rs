//! S3-/Payload-Verkabelung der Setup-Nodes. S3 läuft ausschließlich über
//! `kv-store` (SigV4) — kein aws-cli, kein zweiter HTTP-Client.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kv_store::s3::S3Endpoint;
use serde_json::Value;

#[derive(Clone)]
pub struct S3Cfg {
    pub endpoint: S3Endpoint,
    pub bucket: String,
    pub prefix: String,
}

impl S3Cfg {
    pub fn aus_datei(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("s3 config {path}: {e}"))?;
        let cfg: Value = serde_json::from_str(&raw).map_err(|e| format!("s3 parse: {e}"))?;
        let endpoint = S3Endpoint {
            host: cfg["host"].as_str().ok_or("s3.host fehlt")?.to_string(),
            region: cfg["region"].as_str().unwrap_or("us-east-1").to_string(),
            access_key: cfg["access_key"]
                .as_str()
                .ok_or("s3.access_key fehlt")?
                .to_string(),
            secret_key: cfg["secret_key"]
                .as_str()
                .ok_or("s3.secret_key fehlt")?
                .to_string(),
        };
        Ok(Self {
            endpoint,
            bucket: cfg["bucket"].as_str().unwrap_or_default().to_string(),
            prefix: cfg["prefix"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Override aus Request/Config: bucket/prefix/host/region/keys gewinnen.
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

    pub async fn put(&self, name: &str, data: Vec<u8>) -> Result<String, String> {
        let key = self.key(name);
        self.endpoint
            .put_object(&self.bucket, &key, data)
            .await
            .map_err(|e| format!("S3 PUT {key}: {e}"))?;
        Ok(key)
    }

    pub async fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        let key = self.key(name);
        self.endpoint
            .get_object(&self.bucket, &key)
            .await
            .map_err(|e| format!("S3 GET {key}: {e}"))
    }

    pub async fn exists(&self, name: &str) -> bool {
        self.get(name).await.is_ok()
    }

    pub async fn list(&self, name_prefix: &str) -> Result<Vec<(String, u64)>, String> {
        let key = self.key(name_prefix);
        let objs = self
            .endpoint
            .list_objects(&self.bucket, &key)
            .await
            .map_err(|e| format!("S3 LIST {key}: {e}"))?;
        Ok(objs.into_iter().map(|o| (o.key, o.size)).collect())
    }

    pub async fn delete(&self, name: &str) -> Result<(), String> {
        let key = self.key(name);
        self.endpoint
            .delete_object(&self.bucket, &key)
            .await
            .map_err(|e| format!("S3 DELETE {key}: {e}"))
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
