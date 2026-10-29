//! Big-Bang-Migration: jedes asymmetrische Alt-Siegel (v1/v2) wird geöffnet
//! und als hybride v3-Box (ECC P-256 + ML-KEM-1024) neu gesiegelt. Identität,
//! AAD und Klartext bleiben identisch — nur die Versiegelung ändert sich.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use z8run_core::nodes::setup_nodes::setup_crypto::{hashdatei_parsen, kette, sha_hex};
use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;

use crate::keys::KeyMap;

#[derive(Default)]
pub struct Bericht {
    pub dateien: Vec<Value>,
    pub boxen: usize,
    pub v3_neu: usize,
    pub fehler: Vec<String>,
    pub unveraendert: usize,
    pub uebersprungen: Vec<Value>,
}

fn ist_asym(b: &Value) -> bool {
    let algo = b["algo"].as_str().unwrap_or("");
    if b["v"].as_u64() == Some(3) && algo == kette::umschlag::ALGO_V3 {
        return false;
    }
    (b.get("v").is_none() && algo == kette::umschlag::ALGO_V1)
        || (b["v"].as_u64() == Some(2) && algo == kette::umschlag::ALGO_V2)
}

fn migriere_text(text: &str, km: &mut KeyMap, b: &mut Bericht) -> Result<Option<String>, String> {
    if !text.starts_with("Argon2IDHashDatei/3") {
        return Ok(None);
    }
    let (addrs, blocks) = hashdatei_parsen(text);
    let mut neu_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut geaendert = false;
    for (name, chiffre) in &blocks {
        let mut box_val = crate::box_aus_b64(chiffre)?;
        if !ist_asym(&box_val) {
            continue;
        }
        let target = addrs
            .iter()
            .find(|(_, n)| n == name)
            .map(|(a, _)| a.clone())
            .ok_or_else(|| format!("Box {name}: keine Ziel-Identität in Secretboxes"))?;
        let Some((_, pem)) = km.pems.get(&target).cloned() else {
            b.uebersprungen.push(json!({"box": name, "ziel": target, "grund": "kein Halter-PEM (dev-Artefakt verwaist)"}));
            continue;
        };
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::SecretKey::from_sec1_pem(&pem)
            .ok()
            .or_else(|| p256::SecretKey::from_pkcs8_pem(&pem).ok())
            .ok_or_else(|| format!("Box {name}: PEM nicht lesbar"))?;
        let dk = if box_val["v"].as_u64() == Some(2) {
            km.pqc_fuer(&target)?.dk.clone()
        } else {
            Vec::new()
        };
        let aad = box_val["aad"].as_str().unwrap_or_default().to_string();
        let plain = kette::umschlag::oeffnen(&box_val, &sk, &dk)
            .map_err(|e| format!("Box {name} ({target}) öffnet nicht: {e}"))?;
        let pqc = km.pqc_fuer(&target)?;
        let ek = B64.decode(&pqc.ek_b64).map_err(|e| e.to_string())?;
        box_val = kette::umschlag::siegeln_v3(
            &mut rand::rngs::OsRng,
            &sk.public_key(),
            &ek,
            &plain,
            &aad,
        )?;
        if kette::umschlag::oeffnen(&box_val, &sk, &pqc.dk)? != plain {
            return Err(format!("Box {name}: Gegenprobe nach v3 fehlgeschlagen"));
        }
        neu_map.insert(name.clone(), crate::box_b64(&box_val)?);
        geaendert = true;
    }
    if !geaendert {
        return Ok(None);
    }
    let behalten: Vec<(String, String)> = blocks
        .into_iter()
        .filter(|(n, _)| {
            // Blöcke ohne migrierbare Box werden NICHT als Alt-Format behalten.
            let c = addrs.iter().any(|(_, bn)| bn == n);
            c && (neu_map.contains_key(n) || {
                crate::box_aus_b64(&blocks_map_get(text, n)).map(|v| !ist_asym(&v)).unwrap_or(true)
            })
        })
        .collect();
    let chiffren: Vec<(String, String)> = behalten
        .iter()
        .map(|(n, c)| (n.clone(), neu_map.get(n).cloned().unwrap_or_else(|| c.clone())))
        .collect();
    let ziele: std::collections::HashSet<String> = chiffren.iter().map(|(n, _)| n.clone()).collect();
    let addrs: Vec<(String, String)> = addrs
        .into_iter()
        .filter(|(_, n)| ziele.contains(n))
        .collect();
    Ok(Some(z8run_core::nodes::setup_nodes::setup_crypto::hashdatei_bauen(
        &addrs, &chiffren,
    )))
}

fn blocks_map_get(text: &str, name: &str) -> String {
    hashdatei_parsen(text)
        .1
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, c)| c)
        .unwrap_or_default()
}

pub async fn s3(cfg: &S3Cfg, km: &mut KeyMap, b: &mut Bericht) {
    let keys = match cfg.list("").await {
        Ok(k) => k,
        Err(e) => {
            b.fehler.push(format!("S3 LIST: {e}"));
            return;
        }
    };
    for (full, _) in keys {
        if !full.ends_with(".txt") {
            continue;
        }
        let rel = full.strip_prefix(&cfg.prefix).unwrap_or(&full).to_string();
        let data = match cfg.get(&rel).await {
            Ok(d) => d,
            Err(e) => {
                b.fehler.push(format!("{rel}: GET {e}"));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&data);
        match migriere_text(&text, km, b) {
            Ok(Some(neu)) => {
                if let Err(e) = cfg.put(&rel, neu.clone().into_bytes()).await {
                    b.fehler.push(format!("{rel}: PUT {e}"));
                    continue;
                }
                b.v3_neu += 1;
                b.dateien.push(json!({
                    "key": rel, "vorher": sha_hex(&data), "nachher": sha_hex(neu.as_bytes())
                }));
            }
            Ok(None) => b.unveraendert += 1,
            Err(e) => b.fehler.push(format!("{rel}: {e}")),
        }
    }
    let _ = b.boxen;
}

fn txt_dateien(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            txt_dateien(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("txt") {
            out.push(p);
        }
    }
}

pub fn lokal(root: &Path, km: &mut KeyMap, b: &mut Bericht) {
    let mut dateien = Vec::new();
    txt_dateien(root, &mut dateien);
    for p in dateien {
        // Nur Hashdateien (kein README o. ä.)
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        if !text.starts_with("Argon2IDHashDatei/3") {
            continue;
        }
        match migriere_text(&text, km, b) {
            Ok(Some(neu)) => {
                if let Err(e) = std::fs::write(&p, &neu) {
                    b.fehler.push(format!("{}: WRITE {e}", p.display()));
                    continue;
                }
                b.v3_neu += 1;
                b.dateien.push(json!({
                    "datei": p.display().to_string(),
                    "vorher": sha_hex(text.as_bytes()), "nachher": sha_hex(neu.as_bytes())
                }));
            }
            Ok(None) => b.unveraendert += 1,
            Err(e) => b.fehler.push(format!("{}: {e}", p.display())),
        }
    }
}

/// Gegenprobe: KEINE v1/v2-Box mehr, jede asymmetrische Box ist v3/1024.
pub fn pruefe_text(text: &str, ort: &str, b: &mut Bericht) {
    if !text.starts_with("Argon2IDHashDatei/3") {
        return;
    }
    let (_, blocks) = hashdatei_parsen(text);
    for (name, chiffre) in blocks {
        let Ok(box_val) = crate::box_aus_b64(&chiffre) else { continue };
        let algo = box_val["algo"].as_str().unwrap_or("");
        if algo.contains("AES-256-GCM-Argon2id") {
            continue;
        }
        if ist_asym(&box_val) {
            b.fehler.push(format!("{ort}: {name} noch Alt-Format ({algo})"));
            continue;
        }
        if box_val["v"].as_u64() == Some(3) {
            let ct = box_val["kem_ct"].as_str().unwrap_or_default();
            let len = B64.decode(ct).map(|v| v.len()).unwrap_or(0);
            if box_val["kem"] != "ML-KEM-1024" || len != kette::umschlag::KEM1024_CT_LEN {
                b.fehler.push(format!("{ort}: {name} v3 ohne echten 1024-KEM-Ciphertext"));
            } else {
                b.v3_neu += 1;
            }
        }
    }
}
