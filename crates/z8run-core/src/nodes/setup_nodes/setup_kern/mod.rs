//! Setup-Kern (EINE Naht): Keygen + Welt-Bau + Registry — importiert von
//! `bins/z8-setup` UND den Setup-Flow-Nodes. Keine Kopie, kein Parallelcode.

pub mod keys;
pub mod welt;

use serde_json::{json, Value};

pub use super::setup_crypto as sc;
pub use super::setup_io::{datei_bytes, datei_eintrag, S3Cfg};
pub use super::setup_pqc as pqc;
pub use super::setup_registry as reg;
pub use super::setup_world_build::bau_user;

pub struct KeygenOut {
    pub master_hex: String,
    pub pems: Vec<Value>,
    pub setup_pubkeys: Vec<Value>,
    pub files: Vec<Value>,
    pub registry: Value,
}

pub struct WeltOut {
    pub users: Vec<Value>,
    pub files: Vec<Value>,
    pub registry: Value,
    pub addr_space: String,
}

pub fn zahl(req: &Value, pfad: &str, default: usize) -> usize {
    req.get(pfad).and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(default)
}

pub fn text<'a>(req: &'a Value, pfad: &str) -> Option<&'a str> {
    req.get(pfad).and_then(|v| v.as_str())
}

/// Verzeichnisse/Defaults aus dem Request (Binary und Flow nutzen dieselbe Regel).
pub fn pfade(req: &Value) -> (String, String, String) {
    let space = text(req, "space").unwrap_or_default().to_string();
    let base = text(req, "keyOutDir")
        .map(str::to_string)
        .unwrap_or_else(|| format!("/data/z8run/setup-keys/{space}"));
    let db = text(req, "dbOutDir")
        .map(str::to_string)
        .unwrap_or_else(|| format!("{base}/db"));
    let vec0 = text(req, "vec0Path").unwrap_or("/data/z8run/vec0.so").to_string();
    (base, db, vec0)
}

/// Kompletter Erstaufbau: Registry prüfen, Keys, Welt, Quorum-Write.
pub async fn init_welt(cfg: &S3Cfg, req: &Value) -> Result<Value, String> {
    let k = keys::erzeugen(cfg, req).await?;
    let w = welt::bauen(cfg, req, &k).await?;
    let registry_text = sc::box_b64(
        &sc::registry_siegeln(&k.master_hex, &w.registry).map_err(|e| format!("registry: {e}"))?,
    )?;
    let registry_key = reg::REGISTRY_KEY.to_string();
    let mut files: Vec<Value> = w
        .files
        .into_iter()
        .filter(|f| f["key"].as_str() != Some(registry_key.as_str()))
        .collect();
    files.push(datei_eintrag(registry_key, registry_text.into_bytes(), "utf8"));

    let mut puts = Vec::new();
    let mut degraded = false;
    for f in &files {
        let key = f["key"].as_str().ok_or("file ohne key")?;
        let data = datei_bytes(f)?;
        let info = cfg
            .put_quorum(key, data)
            .await
            .map_err(|e| format!("{key}: {e}"))?;
        degraded |= info.degraded;
        puts.push(json!({
            "key": key,
            "sha256": f["sha256"],
            "replicas_ok": info.replicas_ok,
            "replicas_failed": info.replicas_failed,
            "degraded": info.degraded,
        }));
    }
    let dateien: Vec<Value> = files
        .iter()
        .map(|f| json!({"key": f["key"], "sha256": f["sha256"], "bytes": f["bytes"]}))
        .collect();
    Ok(json!({
        "ok": true,
        "space": req["space"],
        "addr_space": w.addr_space.clone(),
        "shared": false,
        "initialized": true,
        "users": w.users.clone(),
        "setup_pems": k.pems,
        "setup_pubkeys": k.setup_pubkeys,
        "files": dateien,
        "s3_put": puts,
        "provider_degraded": degraded,
        "world": {
            "space": req["space"],
            "addr_space": w.addr_space.clone(),
            "shared": false,
            "users": w.users,
            "setup_pubkeys": k.setup_pubkeys,
            "files": dateien,
        },
    }))
}
