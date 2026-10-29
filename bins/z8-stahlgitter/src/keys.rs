//! Schlüssel-Inventar für die Migration: PEM → klassischer Pubkey,
//! dazu je Identität ein ML-KEM-1024-Paar beim Halter (`<stem>.kem` + JSON).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use z8run_core::nodes::setup_nodes::setup_crypto::kette;

pub struct Pqc {
    pub ek_b64: String,
    pub dk: Vec<u8>,
}

#[derive(Default)]
pub struct KeyMap {
    pub pems: HashMap<String, (PathBuf, String)>,
    pub pqc: HashMap<String, Pqc>,
    pub erzeugt: Vec<Value>,
}

fn pems_in(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            pems_in(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("pem") {
            out.push(p);
        }
    }
}

fn secret(pem: &str) -> Option<p256::SecretKey> {
    use p256::pkcs8::DecodePrivateKey;
    p256::SecretKey::from_sec1_pem(pem)
        .ok()
        .or_else(|| p256::SecretKey::from_pkcs8_pem(pem).ok())
}

pub fn laden(dirs: &[PathBuf]) -> Result<KeyMap, String> {
    let mut km = KeyMap::default();
    let mut dateien = Vec::new();
    for d in dirs {
        pems_in(d, &mut dateien);
    }
    for p in dateien {
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Some(sk) = secret(&text) else { continue };
        let pub_b64 = B64.encode(p256::PublicKey::from(sk.public_key()).to_sec1_bytes());
        km.pems.entry(pub_b64).or_insert((p.clone(), text));
    }
    Ok(km)
}

impl KeyMap {
/// Liefert (ek_b64, dk) für einen klassischen Pubkey; erzeugt das Paar beim
/// Halter, falls es noch nicht existiert. Schreibt `<stem>.kem` (0600).
pub fn pqc_fuer(&mut self, pub_b64: &str) -> Result<&Pqc, String> {
    if self.pqc.contains_key(pub_b64) {
        return Ok(self.pqc.get(pub_b64).unwrap());
    }
    let (pem_path, _) = self
        .pems
        .get(pub_b64)
        .ok_or_else(|| format!("kein privater PEM für Pubkey {pub_b64}"))?;
    let dk_path = pem_path.with_extension("kem");
    // Ein vorhandenes Paar derselben Identität wiederverwenden (Sidecar).
    let side = pem_path.with_extension("kem.json");
    let vorhanden = if dk_path.exists() && side.exists() {
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(&side).unwrap_or_default(),
        )
        .unwrap_or(Value::Null);
        match (
            v["klassisch"].as_str(),
            v["pqc_pub_b64"].as_str(),
            std::fs::read_to_string(&dk_path).ok().and_then(|t| B64.decode(t.trim()).ok()),
        ) {
            (Some(k), Some(ek), Some(dk)) if k == pub_b64 => Some((ek.to_string(), dk)),
            _ => None,
        }
    } else {
        None
    };
    let (ek_b64, dk) = match vorhanden {
        Some(v) => v,
        None => {
            let p = kette::umschlag::kem_paar_1024(&mut rand::rngs::OsRng);
            (B64.encode(&p.ek), p.dk)
        }
    };
    std::fs::write(&dk_path, B64.encode(&dk)).map_err(|e| format!("kem {dk_path:?}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dk_path, std::fs::Permissions::from_mode(0o600));
    }
    let meta = json!({
        "klassisch": pub_b64,
        "pqc_pub_b64": ek_b64,
        "dk_path": dk_path.to_string_lossy(),
        "pem_path": pem_path.to_string_lossy(),
    });
    let _ = std::fs::write(&side, serde_json::to_vec_pretty(&meta).unwrap());
    self.erzeugt.push(meta);
    self.pqc.insert(
        pub_b64.to_string(),
        Pqc { ek_b64, dk },
    );
    Ok(self.pqc.get(pub_b64).unwrap())
}

}

/// Ergänzt `zugangsdaten/fixture.json` (falls vorhanden) um die PQC-Pfade.
pub fn fixture_aktualisieren(key_dirs: &[PathBuf]) -> Result<(), String> {
    for kd in key_dirs {
        let Some(parent) = kd.parent() else { continue };
        let fix = parent.join("zugangsdaten").join("fixture.json");
        if !fix.exists() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&fix) else { continue };
        let Ok(mut v) = serde_json::from_str::<Value>(&raw) else { continue };
        if let Some(users) = v["users"].as_array_mut() {
            for u in users {
                let Some(keys) = u["keys"].as_array().cloned() else { continue };
                let mut pqc_keys = Vec::new();
                for k in keys {
                    let Some(rel) = k.as_str() else { continue };
                    let pem = parent.join(rel);
                    let side = pem.with_extension("kem.json");
                    if let Ok(meta) = serde_json::from_str::<Value>(&std::fs::read_to_string(&side).unwrap_or_default()) {
                        pqc_keys.push(json!({
                            "pem": rel,
                            "pqc_pub_b64": meta["pqc_pub_b64"],
                            "pqc_dk_path": meta["dk_path"],
                        }));
                    }
                }
                if !pqc_keys.is_empty() {
                    u["pqc_keys"] = json!(pqc_keys);
                }
            }
        }
        v["stahlgitter"] = json!({"format":"v3-hybrid-ecc-p256-mlkem1024","updated_at":chrono_now()});
        let _ = std::fs::write(&fix, serde_json::to_vec_pretty(&v).unwrap());
    }
    Ok(())
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("unix:{s}")
}
