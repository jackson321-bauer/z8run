//! Verschlüsselte Setup-Registry und Setup-Shards.
//!
//! Die Registry liegt NUR verschlüsselt im S3 (symmetrisch mit dem
//! Setup-Master aus der Shamir-Teilung). Schreiben ist damit technisch nur
//! mit Setup-Keys möglich — Klartext-Schreibzugriff existiert nicht.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::S3Cfg;

pub const REGISTRY_KEY: &str = "setup/registry.txt";
pub const SHARDS_KEY: &str = "setup/setup-shards.txt";

pub fn cfg_aus(s3_config: &str, req: &Value) -> Result<S3Cfg, String> {
    let base = S3Cfg::aus_datei(s3_config)?;
    let ov = req.get("s3").unwrap_or(req);
    base.mit_override(ov)
}

/// Liest die Registry-Box (noch verschlüsselt) aus dem S3.
pub async fn lade_registry_box(cfg: &S3Cfg, key: &str) -> Result<Value, String> {
    let raw = cfg.get(key).await?;
    let text = String::from_utf8_lossy(&raw);
    sc::box_aus_b64(text.trim())
}

pub async fn lade_registry(cfg: &S3Cfg, key: &str, master_hex: &str) -> Result<Value, String> {
    let box_val = lade_registry_box(cfg, key).await?;
    sc::registry_oeffne(master_hex, &box_val)
}

pub async fn speichere_registry(
    cfg: &S3Cfg,
    key: &str,
    master_hex: &str,
    registry: &Value,
) -> Result<String, String> {
    let box_val = sc::registry_siegeln(master_hex, registry)?;
    let text = sc::box_b64(&box_val)?;
    let sha = sc::sha_hex(text.as_bytes());
    cfg.put(key, text.into_bytes()).await?;
    Ok(sha)
}

/// Stellt den Setup-Master aus mindestens zwei Setup-PEMs wieder her.
/// Jedes PEM öffnet genau seinen Share in `setup-shards.txt`.
pub async fn master_aus_pems(
    cfg: &S3Cfg,
    shards_key: &str,
    pems: &[String],
) -> Result<Vec<u8>, String> {
    let raw = cfg.get(shards_key).await?;
    let text = String::from_utf8_lossy(&raw);
    let (addrs, blocks) = sc::hashdatei_parsen(&text);
    let map: std::collections::HashMap<String, String> = blocks.into_iter().collect();
    let mut shares: Vec<sc::kette::shamir::Share> = Vec::new();
    for pem in pems {
        let pub_b64 = sc::pem_pub_b64(pem)?;
        let Some((_, block)) = addrs.iter().find(|(a, _)| a == &pub_b64) else {
            continue;
        };
        let Some(chiffre) = map.get(block) else {
            continue;
        };
        let box_val = sc::box_aus_b64(chiffre)?;
        let plain = sc::kette::hwbox_oeffne(&box_val, pem)?;
        let share: Value = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        let y = B64
            .decode(share["y_b64"].as_str().ok_or("share.y_b64 fehlt")?)
            .map_err(|e| e.to_string())?;
        let x = share["x"].as_u64().ok_or("share.x fehlt")? as u8;
        if !shares.iter().any(|s| s.x == x) {
            shares.push(sc::kette::shamir::Share { x, y });
        }
    }
    if shares.len() < 2 {
        return Err(format!(
            "Setup-Quorum nicht erreicht: {} gültige Setup-Keys, 2 nötig",
            shares.len()
        ));
    }
    let master = sc::kette::shamir::combine2(&shares[0], &shares[1])?;
    for i in 1..shares.len() {
        for j in (i + 1)..shares.len() {
            let m = sc::kette::shamir::combine2(&shares[i], &shares[j])?;
            if m != master {
                return Err("Setup-Keys gehören zu unterschiedlichen Welten".into());
            }
        }
    }
    Ok(master)
}

/// Setup-Pubkeys aus einem PEM-Array (Strings oder Objekte mit `pem`).
pub fn pems_aus(req: &Value, path: &str) -> Vec<String> {
    super::setup_io::pfad(req, path)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    e.as_str()
                        .map(str::to_string)
                        .or_else(|| e.get("pem").and_then(|p| p.as_str()).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Baut das Setup-Shard-File: je Setup-Pubkey eine ECIES-Box mit dem Share.
pub fn shards_bauen(master: &[u8], n: usize, pems: &[sc::PemPaar]) -> Result<(String, Vec<Value>), String> {
    let xs: Vec<u8> = (1..=n as u8).collect();
    let shares = sc::kette::shamir::split2(master, &xs)?;
    let mut addrs = Vec::new();
    let mut chiffren = Vec::new();
    let mut pubs = Vec::new();
    for (i, paar) in pems.iter().enumerate() {
        let share = json!({ "x": shares[i].x, "y_b64": B64.encode(&shares[i].y) });
        let box_val = sc::hwbox(&paar.pub_b64, &share, "kv3-setup")?;
        addrs.push((paar.pub_b64.clone(), format!("Block-{}", i + 1)));
        chiffren.push((format!("Block-{}", i + 1), sc::box_b64(&box_val)?));
        pubs.push(json!({
            "name": format!("setup-hw{}", i + 1),
            "pub_b64": paar.pub_b64,
            "x": shares[i].x,
        }));
    }
    Ok((sc::hashdatei_bauen(&addrs, &chiffren), pubs))
}

/// S3-Ziel aus der Registry (Wahrheit) mit optionalem Request-Override.
pub fn cfg_aus_registry(
    s3_config: &str,
    req: &Value,
    registry: &Value,
) -> Result<S3Cfg, String> {
    let fallback = S3Cfg::aus_datei(s3_config)?;
    let mut cfg = fallback.clone();
    if let Some(s3) = registry.get("s3") {
        if let Some(v) = s3.get("host").and_then(|v| v.as_str()) {
            cfg.endpoint.host = v.to_string();
        }
        if let Some(v) = s3.get("region").and_then(|v| v.as_str()) {
            cfg.endpoint.region = v.to_string();
        }
        if let Some(v) = s3.get("access_key").and_then(|v| v.as_str()) {
            cfg.endpoint.access_key = v.to_string();
        }
        if let Some(v) = s3.get("secret_key").and_then(|v| v.as_str()) {
            cfg.endpoint.secret_key = v.to_string();
        }
        if let Some(v) = s3.get("bucket").and_then(|v| v.as_str()) {
            cfg.bucket = v.to_string();
        }
        if let Some(v) = s3.get("prefix").and_then(|v| v.as_str()) {
            cfg.prefix = v.to_string();
        }
    }
    let ov = req.get("s3").unwrap_or(req);
    cfg.mit_override(ov)
}
