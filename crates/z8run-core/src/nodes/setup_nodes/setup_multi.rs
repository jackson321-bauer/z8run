//! Multi-Provider-S3 (Steckdosen-Gesetz): Provider-Set + Quorum-Schreiben.
//!
//! Format `s3-multi-providers.json`:
//! `{ "<name>": { "endpoint": "https://host", "region": "...",
//!                 "access_key": "...", "secret_key": "..." }, ... }`
//! Optional: `bucket`, `prefix`, `quorum_min`. Legacy-Einzelconfig
//! (`host`/`region`/`access_key`/`secret_key`/`bucket`/`prefix`) bleibt gültig.
//! Wahrheit (Keys) bleibt in der Config; dieses Modul ist reine Verkabelung.

use kv_store::s3::S3Endpoint;
use serde_json::Value;

#[derive(Clone)]
pub struct MpTarget {
    pub label: String,
    pub endpoint: S3Endpoint,
    pub bucket: String,
}

#[derive(Clone)]
pub struct Multi {
    pub targets: Vec<MpTarget>,
    pub quorum_min: usize,
}

pub struct Parsed {
    pub endpoint: S3Endpoint,
    pub bucket: String,
    pub prefix: String,
    pub multi: Option<Multi>,
}

fn host_aus(endpoint: &str) -> Result<String, String> {
    let u = url::Url::parse(endpoint).map_err(|e| format!("provider endpoint {endpoint}: {e}"))?;
    u.host_str()
        .map(str::to_string)
        .ok_or_else(|| format!("provider endpoint ohne Host: {endpoint}"))
}

fn ist_provider(v: &Value) -> bool {
    v.is_object() && (v.get("endpoint").is_some() || v.get("host").is_some())
}

/// Erkennt Einzel- oder Provider-Set-Config und liefert die Primär-Sicht.
pub fn parse(
    cfg: &Value,
    bucket_ov: Option<&str>,
    prefix_ov: Option<&str>,
) -> Result<Parsed, String> {
    let bucket_ov = bucket_ov.filter(|s| !s.is_empty());
    let prefix_ov = prefix_ov.filter(|s| !s.is_empty());
    if cfg.get("host").is_some() {
        let endpoint = S3Endpoint {
            host: cfg["host"].as_str().ok_or("s3.host fehlt")?.to_string(),
            region: cfg["region"].as_str().unwrap_or("us-east-1").to_string(),
            access_key: cfg["access_key"].as_str().ok_or("s3.access_key fehlt")?.to_string(),
            secret_key: cfg["secret_key"].as_str().ok_or("s3.secret_key fehlt")?.to_string(),
        };
        return Ok(Parsed {
            endpoint,
            bucket: bucket_ov
                .map(str::to_string)
                .or_else(|| cfg["bucket"].as_str().map(str::to_string))
                .unwrap_or_default(),
            prefix: prefix_ov
                .map(str::to_string)
                .or_else(|| cfg["prefix"].as_str().map(str::to_string))
                .unwrap_or_default(),
            multi: None,
        });
    }
    let quelle = cfg.get("providers").filter(|v| v.is_object()).unwrap_or(cfg);
    let top_bucket = bucket_ov
        .map(str::to_string)
        .or_else(|| cfg["bucket"].as_str().map(str::to_string));
    let prefix = prefix_ov
        .map(str::to_string)
        .or_else(|| cfg["prefix"].as_str().map(str::to_string))
        .unwrap_or_default();
    let mut targets = Vec::new();
    let Some(obj) = quelle.as_object() else {
        return Err("Provider-Set ist kein Objekt".into());
    };
    for (name, p) in obj {
        if !ist_provider(p) {
            continue;
        }
        let host = match p.get("endpoint").and_then(|v| v.as_str()) {
            Some(e) => host_aus(e)?,
            None => p["host"].as_str().ok_or("provider.host fehlt")?.to_string(),
        };
        let bucket = p["bucket"]
            .as_str()
            .map(str::to_string)
            .or_else(|| top_bucket.clone())
            .ok_or_else(|| format!("provider {name}: bucket fehlt"))?;
        targets.push(MpTarget {
            label: name.clone(),
            endpoint: S3Endpoint {
                host,
                region: p["region"].as_str().unwrap_or("us-east-1").to_string(),
                access_key: p["access_key"].as_str().unwrap_or_default().to_string(),
                secret_key: p["secret_key"].as_str().unwrap_or_default().to_string(),
            },
            bucket,
        });
    }
    if targets.is_empty() {
        return Err("Provider-Set enthält keinen Provider".into());
    }
    let q = cfg["quorum_min"]
        .as_u64()
        .or_else(|| cfg["quorum"]["threshold"].as_u64())
        .unwrap_or(2) as usize;
    let quorum_min = q.clamp(1, targets.len());
    let ersten = targets[0].clone();
    Ok(Parsed {
        endpoint: ersten.endpoint,
        bucket: ersten.bucket,
        prefix,
        multi: Some(Multi { targets, quorum_min }),
    })
}

/// Metadaten eines Quorum-Writes (provider_degraded-Beweis).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WriteInfo {
    pub key: String,
    pub replicas_ok: Vec<String>,
    pub replicas_failed: Vec<String>,
    pub degraded: bool,
}
