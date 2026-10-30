//! Export-Pyramide: Key-Boxen für den PQC-Container.
//! DEFAULT VERSCHLÜSSELT: (1) v3-Hybrid-Box an Pubkey, (2) Passwort-Box
//! (Argon2id ∥ ML-KEM: Password entsperrt ECC-Privatekey + ML-KEM-dk der
//! v3-Box), (3) Klartext NUR mit explizitem Bestätigungsschritt.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use kv_login::kette::umschlag;

pub enum BoxMode<'a> {
    Pqc { pub_b64: &'a str, kem_ek_b64: &'a str },
    Password { passwort: &'a str },
    Plaintext { bestaetigung: bool },
}

pub enum OpenBox<'a> {
    Pqc { pem: &'a str, kem_dk: &'a [u8] },
    Password { passwort: &'a str },
    Plaintext,
}

fn pw_seal(key: &[u8; 32], plain: &[u8], label: &str) -> Result<Value, String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce: [u8; 12] = rand::random();
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: plain, aad: label.as_bytes() })
        .map_err(|e| format!("AES-GCM {label}: {e}"))?;
    Ok(json!({"nonce": B64.encode(nonce), "box": B64.encode(ct)}))
}

fn pw_open(key: &[u8; 32], v: &Value, label: &str) -> Result<Vec<u8>, String> {
    let nonce: [u8; 12] = B64
        .decode(v["nonce"].as_str().ok_or("nonce fehlt")?)
        .map_err(|e| format!("nonce: {e}"))?
        .try_into()
        .map_err(|_| "nonce Länge falsch".to_string())?;
    let ct = B64.decode(v["box"].as_str().ok_or("box fehlt")?).map_err(|e| e.to_string())?;
    Aes256Gcm::new(key.into())
        .decrypt((&nonce).into(), Payload { msg: &ct, aad: label.as_bytes() })
        .map_err(|_| format!("{label}: Passwort falsch / Box manipuliert"))
}

/// Mindest-Entropie: >= 12 Zeichen UND >= 3 Zeichenklassen (oder >= 16 Zeichen).
pub fn check_password(pw: &str) -> Result<(), String> {
    if pw.len() < 12 {
        return Err("WEAK_PASSWORD: mindestens 12 Zeichen".into());
    }
    let klassen = [
        pw.chars().any(|c| c.is_ascii_lowercase()),
        pw.chars().any(|c| c.is_ascii_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if pw.len() < 16 && klassen < 3 {
        return Err("WEAK_PASSWORD: mindestens 3 Zeichenklassen (oder 16 Zeichen)".into());
    }
    Ok(())
}

pub fn seal_container_key(mode: BoxMode<'_>, ck: &[u8; 32], aad: &str) -> Result<Value, String> {
    match mode {
        BoxMode::Pqc { pub_b64, kem_ek_b64 } => {
            let raw = B64.decode(pub_b64).map_err(|e| format!("Publickey: {e}"))?;
            let ziel = umschlag::p256_pub(&raw)?;
            let ek = B64.decode(kem_ek_b64).map_err(|e| format!("ML-KEM ek: {e}"))?;
            let v3 = umschlag::siegeln_v3(&mut rand::rngs::OsRng, &ziel, &ek, ck, aad)?;
            Ok(json!({"mode": "pqc", "v3": v3}))
        }
        BoxMode::Password { passwort } => {
            check_password(passwort)?;
            let salt = hex::encode(rand::random::<[u8; 16]>());
            let pwkey = kv_login::kette::argon2_raw(passwort, &salt)?;
            let ecc = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let pem = ecc
                .to_sec1_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| format!("ECC-PEM: {e}"))?;
            let kem = umschlag::kem_paar_1024(&mut rand::rngs::OsRng);
            let v3 = umschlag::siegeln_v3(
                &mut rand::rngs::OsRng,
                &ecc.public_key(),
                &kem.ek,
                ck,
                aad,
            )?;
            Ok(json!({
                "mode": "password",
                "salt": salt,
                "v3": v3,
                "dk": pw_seal(&pwkey, &kem.dk, "z8-container-kem-dk")?,
                "pem": pw_seal(&pwkey, pem.to_string().as_bytes(), "z8-container-ecc-pem")?,
            }))
        }
        BoxMode::Plaintext { bestaetigung } => {
            if !bestaetigung {
                return Err("CONFIRM_REQUIRED: Klartext-Export nur mit Bestätigung".into());
            }
            Ok(json!({"mode": "plaintext", "ck": B64.encode(ck)}))
        }
    }
}

pub fn open_container_key(key_box: &Value, mode: OpenBox<'_>) -> Result<[u8; 32], String> {
    let stored = key_box["mode"].as_str().unwrap_or("");
    match (mode, stored) {
        (OpenBox::Pqc { pem, kem_dk }, "pqc") => {
            let ecc = p256::SecretKey::from_sec1_pem(pem)
                .map_err(|e| format!("ECC-Privatekey: {e}"))?;
            let ck = umschlag::oeffnen(&key_box["v3"], &ecc, kem_dk)?;
            ck.as_slice().try_into().map_err(|_| "Container-Key-Länge falsch".to_string())
        }
        (OpenBox::Password { passwort }, "password") => {
            let salt = key_box["salt"].as_str().ok_or("salt fehlt")?;
            let pwkey = kv_login::kette::argon2_raw(passwort, salt)?;
            let dk = pw_open(&pwkey, &key_box["dk"], "z8-container-kem-dk")?;
            let pem = pw_open(&pwkey, &key_box["pem"], "z8-container-ecc-pem")?;
            let ecc = p256::SecretKey::from_sec1_pem(
                std::str::from_utf8(&pem).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("ECC-Privatekey: {e}"))?;
            let ck = umschlag::oeffnen(&key_box["v3"], &ecc, &dk)?;
            ck.as_slice().try_into().map_err(|_| "Container-Key-Länge falsch".to_string())
        }
        (OpenBox::Plaintext, "plaintext") => {
            let raw = B64.decode(key_box["ck"].as_str().ok_or("ck fehlt")?).map_err(|e| e.to_string())?;
            raw.as_slice().try_into().map_err(|_| "Container-Key-Länge falsch".to_string())
        }
        (_, other) => Err(format!("Container-Modus {other} passt nicht zum Öffner")),
    }
}
