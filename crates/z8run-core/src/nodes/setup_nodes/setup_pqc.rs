//! Z8-STAHLGITTER: hybride v3-Boxen (ECC P-256 + ML-KEM-1024).
//!
//! Krypto kommt aus der EINEN Quelle (`kv_login::kette::umschlag`, dort als
//! v3-Erweiterung). Dieses Modul ist nur Verkabelung — der z8-Pfad öffnet
//! ausschließlich v3, ein Nur-ECIES-Öffner existiert hier nicht.
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;

use super::setup_crypto::kette;

/// Ein ML-KEM-1024-Paar für eine Identität (Halter bleibt der Besitzer des
/// Privatekeys — Ablage neben dem PEM, nie im Flow/S3).
pub struct PqcPaar {
    pub ek_b64: String,
    pub dk: Vec<u8>,
}

pub fn gen_pqc() -> Result<PqcPaar, String> {
    let p = kette::umschlag::kem_paar_1024(&mut rand::rngs::OsRng);
    Ok(PqcPaar {
        ek_b64: B64.encode(&p.ek),
        dk: p.dk,
    })
}

/// Versiegelt v3 hybrid an klassischen Pubkey (SEC1/SPKI Base64) UND
/// ML-KEM-1024-ek (Base64, 1568 B).
pub fn hwbox_v3(
    pub_b64: &str,
    pqc_pub_b64: &str,
    block: &Value,
    aad: &str,
) -> Result<Value, String> {
    let raw = B64.decode(pub_b64).map_err(|e| format!("Publickey Base64: {e}"))?;
    let ziel = kette::umschlag::p256_pub(&raw)?;
    let ek = B64
        .decode(pqc_pub_b64)
        .map_err(|e| format!("ML-KEM ek Base64: {e}"))?;
    let bytes = serde_json::to_vec(block).map_err(|e| e.to_string())?;
    kette::umschlag::siegeln_v3(&mut rand::rngs::OsRng, &ziel, &ek, &bytes, aad)
}

/// Erzeugt (falls nicht vom Client vorgegeben) das ML-KEM-1024-Paar einer
/// Identität. Der Privatekey landet NUR beim Halter (`<label>.kem`, 0600),
/// der Pubkey geht in Registry/Boxen.
pub fn pqc_paar_fuer(
    label: &str,
    dir: &str,
    provided_pub_b64: Option<&str>,
) -> Result<(String, Option<String>), String> {
    if let Some(p) = provided_pub_b64 {
        return Ok((p.to_string(), None));
    }
    let paar = gen_pqc()?;
    std::fs::create_dir_all(dir).map_err(|e| format!("pqc dir {dir}: {e}"))?;
    let path = format!("{dir}/{label}.kem");
    std::fs::write(&path, B64.encode(&paar.dk)).map_err(|e| format!("write {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((paar.ek_b64, Some(path)))
}

/// Liest den ML-KEM-Privatekey des Halters (Base64 in `<label>.kem`).
pub fn lese_kem_dk(path: &str) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("kem dk {path}: {e}"))?;
    B64.decode(text.trim())
        .map_err(|e| format!("kem dk {path} (Base64): {e}"))
}

/// Öffnet AUSSCHLIESSLICH v3-Boxen (v-Feld=3, algo v3). v1/v2 werden hier
/// bewusst abgewiesen — der z8-Pfad kennt keinen Nur-ECIES-Öffner mehr.
pub fn hwbox_oeffne_v3(box_val: &Value, pem: &str, kem_dk: &[u8]) -> Result<Value, String> {
    let algo = box_val["algo"].as_str().unwrap_or("");
    if box_val["v"].as_u64() != Some(3) || algo != kette::umschlag::ALGO_V3 {
        return Err("z8-Stahlgitter: nur v3-Hybrid-Boxen (ECC+ML-KEM-1024) erlaubt".into());
    }
    let privat = p256::SecretKey::from_sec1_pem(pem).map_err(|e| format!("PEM: {e}"))?;
    let plain = kette::umschlag::oeffnen(box_val, &privat, kem_dk)?;
    serde_json::from_slice(&plain).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identitaet() -> (String, PqcPaar) {
        let pem = super::super::setup_crypto::gen_pem().unwrap();
        let p = gen_pqc().unwrap();
        (pem.pem, p)
    }

    #[test]
    fn s1_v3_rundlauf_und_hybrid_zwang() {
        let (pem, p) = identitaet();
        let pub_b64 = super::super::setup_crypto::pem_pub_b64(&pem).unwrap();
        let block = json!({"shamir_hw": {"x": 2, "y_b64": "QUJD"}});
        let bx = hwbox_v3(&pub_b64, &p.ek_b64, &block, "kv3-hw").unwrap();
        assert_eq!(bx["v"], 3);
        assert_eq!(bx["kem"], "ML-KEM-1024");
        // Hybrid-Roundtrip
        let gut = hwbox_oeffne_v3(&bx, &pem, &p.dk).unwrap();
        assert_eq!(gut["shamir_hw"]["x"], 2);
        // Nur klassisch (PQC weggelassen) → Fehler
        assert!(hwbox_oeffne_v3(&bx, &pem, &[]).is_err());
        // Nur PQC (falscher ECC-Key) → Fehler
        let (fremd_pem, _) = identitaet();
        assert!(hwbox_oeffne_v3(&bx, &fremd_pem, &p.dk).is_err());
        // Manipulierter KEM-Ciphertext → Fehler
        let mut boese = bx.clone();
        let mut ct = B64.decode(boese["kem_ct"].as_str().unwrap()).unwrap();
        ct[0] ^= 1;
        boese["kem_ct"] = json!(B64.encode(&ct));
        assert!(hwbox_oeffne_v3(&boese, &pem, &p.dk).is_err());
        // v2-Felder in v3 → Fehler (strikter Dispatch)
        let mut v3_mit_v2 = bx.clone();
        v3_mit_v2["kem"] = json!("ML-KEM-768");
        assert!(hwbox_oeffne_v3(&v3_mit_v2, &pem, &p.dk).is_err());
    }

    #[test]
    fn s1_v1_und_v2_werden_vom_z8_pfad_abgewiesen() {
        let (pem, _) = identitaet();
        let v1 = json!({"algo": "ECIES-P256-HKDF-SHA256-AES256GCM",
                       "ephem": "AAAA", "nonce": "AAAA", "box": "AAAA", "aad": "x"});
        assert!(hwbox_oeffne_v3(&v1, &pem, &[0u8; 3168]).is_err());
        let v2 = json!({"v": 2, "algo": "hybrid-ecc-p256-mlkem768-hkdf-sha256-aes256gcm",
                        "kem": "ML-KEM-768", "ephem": "AAAA", "kem_ct": "AAAA",
                        "nonce": "AAAA", "box": "AAAA", "aad": "x"});
        assert!(hwbox_oeffne_v3(&v2, &pem, &[0u8; 3168]).is_err());
    }
}
