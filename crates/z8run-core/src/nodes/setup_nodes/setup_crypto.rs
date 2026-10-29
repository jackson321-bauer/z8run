//! Gemeinsame Helfer der Z8-Setup-Nodes.
//!
//! Krypto kommt AUSSCHLIESSLICH aus `kv_login::kette` — derselben Quelle wie
//! Produktion (smart-frontend/src/kette.rs). Dieses Modul enthält nur
//! Verkabelung: Argon2IDHashDatei/3-Format, Salt-/Adressableitung und
//! dünne Wrapper um Öffnen/Siegeln.
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::Digest;

pub use kv_login::kette;

pub const HASH_DATEI_KOPF: &str = "Argon2IDHashDatei/3";

pub fn sha_hex(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

pub fn salt_space(space: &str) -> String {
    sha_hex(format!("kv3-salt:{space}").as_bytes())
}

pub fn salt_user(space_salt: &str, name: &str) -> String {
    sha_hex(format!("{space_salt}:user:{name}").as_bytes())
}


pub struct PemPaar {
    pub pem: String,
    pub pub_b64: String,
}

/// Erzeugt ein ECDSA-P256-PEM-Paar (SEC1) wie seed_welt2.
///
/// p256 laesst in SEC1 die benannte Kurve weg; OpenSSL/Python koennen solche
/// PEMs nicht laden. Wir setzen `parameters [0] prime256v1` explizit ein —
/// kette/p256 und OpenSSL verstehen das identisch.
pub fn gen_pem() -> Result<PemPaar, String> {
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let der = secret.to_sec1_der().map_err(|e| format!("SEC1: {e}"))?;
    // 0x30 len | 02 01 01 | 04 20 <32> | [1] BIT STRING
    let params: [u8; 12] = [0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let content_len = der.len() - 2 + params.len();
    if content_len >= 0x80 {
        return Err("SEC1: unerwartete Länge".into());
    }
    let mut voll = Vec::with_capacity(content_len + 2);
    voll.push(0x30);
    voll.push(content_len as u8);
    voll.extend_from_slice(&der[2..39]);
    voll.extend_from_slice(&params);
    voll.extend_from_slice(&der[39..]);
    let b64 = B64.encode(&voll);
    let mut pem = String::from("-----BEGIN EC PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END EC PRIVATE KEY-----\n");
    let pub_b64 = B64.encode(p256::PublicKey::from(secret.public_key()).to_sec1_bytes());
    Ok(PemPaar { pem, pub_b64 })
}

pub fn pem_pub_b64(pem: &str) -> Result<String, String> {
    let secret = p256::SecretKey::from_sec1_pem(pem).map_err(|e| format!("PEM: {e}"))?;
    Ok(B64.encode(
        p256::PublicKey::from(secret.public_key()).to_sec1_bytes(),
    ))
}

/// Signiert eine Nachricht mit dem PEM (ECDSA P-256/SHA-256, DER, Base64).
pub fn signiere(pem: &str, nachricht: &[u8]) -> Result<String, String> {
    use p256::ecdsa::signature::Signer;
    let secret = p256::SecretKey::from_sec1_pem(pem).map_err(|e| format!("PEM: {e}"))?;
    let key = p256::ecdsa::SigningKey::from(&secret);
    let sig: p256::ecdsa::Signature = key.sign(nachricht);
    Ok(B64.encode(sig.to_der().as_bytes()))
}

/// Prüft eine DER-Base64-Signatur gegen einen SEC1-Pubkey (Base64).
pub fn pruefe_signatur(pub_b64: &str, nachricht: &[u8], sig_b64: &str) -> bool {
    use p256::ecdsa::signature::Verifier;
    let ok = (|| -> Result<(), String> {
        let raw = B64.decode(pub_b64).map_err(|e| e.to_string())?;
        let pubkey = p256::PublicKey::from_sec1_bytes(&raw).map_err(|e| e.to_string())?;
        let verifier = p256::ecdsa::VerifyingKey::from(&pubkey);
        let sig_raw = B64.decode(sig_b64).map_err(|e| e.to_string())?;
        let sig = p256::ecdsa::Signature::from_der(&sig_raw).map_err(|e| e.to_string())?;
        verifier.verify(nachricht, &sig).map_err(|e| e.to_string())
    })();
    ok.is_ok()
}

pub use super::setup_hashfmt::{hashdatei_bauen, hashdatei_parsen, HashEintraege, ParsedHashdatei};

pub fn box_b64(wert: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(wert).map_err(|e| e.to_string())?;
    Ok(B64.encode(bytes))
}

pub fn box_aus_b64(text: &str) -> Result<Value, String> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = B64.decode(clean.trim()).map_err(|e| e.to_string())?;
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}

pub fn passbox(passwort: &str, salt: &str, block: &Value, aad: &str) -> Result<Value, String> {
    let bytes = serde_json::to_vec(block).map_err(|e| e.to_string())?;
    kette::passbox_siegel(passwort, salt, &bytes, aad)
}

pub fn passbox_oeffne(box_val: &Value, passwort: &str, salt: &str) -> Result<Value, String> {
    let plain = kette::passbox_oeffne(box_val, passwort, salt)?;
    serde_json::from_slice(&plain).map_err(|e| e.to_string())
}

/// Z8-STAHLGITTER: JEDE neue Hardware-Box ist hybrid v3 (ECC+ML-KEM-1024).
pub fn hwbox(
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

/// Verschlüsselte Setup-Registry: symmetrisch mit dem Setup-Master.
pub fn registry_siegeln(master_hex: &str, inhalt: &Value) -> Result<Value, String> {
    passbox(master_hex, "kv3-setup-registry", inhalt, "kv3-setup-registry")
}

pub fn registry_oeffne(master_hex: &str, box_val: &Value) -> Result<Value, String> {
    passbox_oeffne(box_val, master_hex, "kv3-setup-registry")
}

pub fn leeres_registry(space: &str) -> Value {
    json!({
        "format": "kv3-setup-registry/1",
        "space": space,
        "threshold": 2,
        "setup_keys": [],
        "s3": {},
        "plugins": {},
        "webauthn": {},
        "updated_at": chrono::Utc::now().to_rfc3339(),
    })
}
