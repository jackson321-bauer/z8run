//! Browser-Passbox-Login (FEST 15-Vorstufe): Passbox -> S3-Hashdatei ->
//! Argon2id -> (Provider- + HW-Shard) -> Master -> Kern-Start.
//!
//! KEIN Direkt-Master-Eingang. Die Hashdatei kommt aus S3 und wird NIE
//! lokal gespeichert (nur RAM). Krypto identisch zur nativen kette.rs.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::Argon2;
use base64::Engine as _;
use serde_json::Value;

use crate::opfs;
use crate::sigv4::Signer;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const ARGON2_M_KIB: u32 = 19456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

#[derive(Debug)]
pub struct LoginError {
    pub code: &'static str,
    pub message: String,
}

impl LoginError {
    fn auth(msg: impl Into<String>) -> Self {
        Self { code: "UNAUTHORIZED", message: msg.into() }
    }
    fn unavailable(msg: impl Into<String>) -> Self {
        Self { code: "UNAVAILABLE", message: msg.into() }
    }
}

pub fn argon2_raw(input: &str, salt: &str) -> Result<[u8; 32], String> {
    let params = argon2::Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| format!("Argon2id-Profil: {e}"))?;
    let a = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(input.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|e| format!("Argon2id: {e}"))?;
    Ok(out)
}

/// Argon2id -> Base32 -> 32 Zeichen (klein): Bucket-/User-Adresse.
pub fn adresse(name: &str, salt: &str) -> Result<String, String> {
    use data_encoding::BASE32_NOPAD;
    let raw = argon2_raw(name, salt)?;
    let b32 = BASE32_NOPAD.encode(&raw);
    Ok(b32.to_lowercase().chars().take(32).collect())
}

pub fn passbox_oeffne(box_json: &Value, passwort: &str, salt: &str) -> Result<Vec<u8>, String> {
    let key = argon2_raw(passwort, salt)?;
    let nonce: [u8; 12] = B64
        .decode(box_json["nonce"].as_str().ok_or("passbox: nonce fehlt")?)
        .map_err(|e| format!("passbox nonce: {e}"))?
        .try_into()
        .map_err(|_| "passbox: nonce Laenge falsch".to_string())?;
    let ct = B64
        .decode(box_json["box"].as_str().ok_or("passbox: box fehlt")?)
        .map_err(|e| format!("passbox box: {e}"))?;
    let aad = box_json["aad"].as_str().ok_or("passbox: aad fehlt")?;
    let aead = Aes256Gcm::new((&key).into());
    aead.decrypt(
        (&nonce).into(),
        Payload {
            msg: &ct,
            aad: aad.as_bytes(),
        },
    )
    .map_err(|_| "Passwort falsch (Secretbox oeffnet nicht)".to_string())
}

mod gf {
    pub fn mul(a: u8, b: u8) -> u8 {
        let (mut a, mut b, mut p) = (a, b, 0u8);
        while b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let mut r = 1u8;
        for _ in 0..254 {
            r = mul(r, a);
        }
        r
    }
}


pub fn combine2(a: (u8, Vec<u8>), b: (u8, Vec<u8>)) -> Result<Vec<u8>, String> {
    if a.0 == 0 || b.0 == 0 || a.0 == b.0 {
        return Err("Shamir: zwei VERSCHIEDENE x>0 noetig".into());
    }
    if a.1.len() != b.1.len() {
        return Err("Shamir: Anteile unterschiedlicher Laenge".into());
    }
    let la = gf::mul(b.0, gf::inv(a.0 ^ b.0));
    let lb = gf::mul(a.0, gf::inv(a.0 ^ b.0));
    Ok(a.1
        .iter()
        .zip(b.1.iter())
        .map(|(ya, yb)| gf::mul(*ya, la) ^ gf::mul(*yb, lb))
        .collect())
}

pub struct LoginOk {
    pub master: zeroize::Zeroizing<Vec<u8>>,
    pub space_addr: String,
    pub user_addr: String,
    pub username: String,
    pub passbox_payload: Value,
}

fn amz_date_now() -> String {
    let iso = js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default();
    let d: String = iso.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() >= 14 {
        format!("{}T{}Z", &d[..8], &d[8..14])
    } else {
        "19700101T000000Z".to_string()
    }
}

/// Echter S3-GET (SigV4 + fetch) — Hashdatei kommt NIE aus dem lokalen Cache.
pub async fn s3_get_bytes(s3: &Value, rel_key: &str) -> Result<Vec<u8>, LoginError> {
    let host = s3["host"].as_str().unwrap_or("");
    let region = s3["region"].as_str().unwrap_or("us-east-1");
    let access = s3["access_key"].as_str().unwrap_or("");
    let secret = s3["secret_key"].as_str().unwrap_or("");
    let bucket = s3["bucket"].as_str().unwrap_or("");
    let prefix = s3["prefix"].as_str().unwrap_or("");
    if host.is_empty() || bucket.is_empty() || access.is_empty() {
        return Err(LoginError::unavailable("S3-Konfiguration fehlt"));
    }
    let full = format!("{prefix}{rel_key}");
    let path = format!("/{bucket}/{full}");
    let amz = amz_date_now();
    let signer = Signer::new(access, secret, region);
    let empty = Signer::payload_hash(b"");
    let (_sig, headers) = signer.authorization(
        "GET",
        host,
        &path,
        "",
        &[],
        &empty,
        &amz,
    );
    let obj = js_sys::Object::new();
    for (k, v) in &headers {
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v));
    }
    let url = format!("https://{host}{path}");
    let res = wasm_bindgen_futures::JsFuture::from(opfs::fetch(
        &url,
        "GET",
        obj.into(),
        JsValue::NULL,
    ))
    .await
    .map_err(|e| LoginError::unavailable(format!("S3 fetch: {e:?}")))?;
    let status = js_sys::Reflect::get(&res, &JsValue::from_str("status"))
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as u16;
    if status != 200 {
        return Err(LoginError::auth(format!("S3 GET {status}")));
    }
    let bytes = js_sys::Reflect::get(&res, &JsValue::from_str("bytes"))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Uint8Array>().ok())
        .map(|a| a.to_vec())
        .unwrap_or_default();
    Ok(bytes)
}

use wasm_bindgen::{JsCast, JsValue};
