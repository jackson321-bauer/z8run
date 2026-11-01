//! Browser-Passbox-Login (FEST 15-Vorstufe): Passbox -> S3-Hashdatei ->
//! Argon2id -> (Provider- + HW-Shard) -> Master -> Kern-Start.
//!
//! KEIN Direkt-Master-Eingang. Die Hashdatei kommt aus S3 und wird NIE
//! lokal gespeichert (nur RAM). Krypto identisch zur nativen kette.rs.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::Argon2;
use base64::Engine as _;
use hkdf::Hkdf;
#[cfg(feature = "test-login")]
use p256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(feature = "test-login")]
use serde_json::json;
use serde_json::Value;
use sha2::Sha256;

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

fn hwbox_oeffne_v1(box_json: &Value, pem: &str) -> Result<Vec<u8>, String> {
    let algo = box_json["algo"].as_str().unwrap_or("");
    if box_json["v"].as_u64().is_some() || !algo.starts_with("ECIES-P256") {
        return Err(format!(
            "HW-Box-Version nicht unterstuetzt (algo={algo}, v={})",
            box_json["v"].as_u64().unwrap_or(0)
        ));
    }
    let ephem_raw = B64
        .decode(box_json["ephem"].as_str().ok_or("hwbox: ephem fehlt")?)
        .map_err(|e| format!("hwbox ephem: {e}"))?;
    let ephem = p256::PublicKey::from_sec1_bytes(&ephem_raw)
        .map_err(|e| format!("hwbox ephem P-256: {e}"))?;
    let nonce: [u8; 12] = B64
        .decode(box_json["nonce"].as_str().ok_or("hwbox: nonce fehlt")?)
        .map_err(|e| format!("hwbox nonce: {e}"))?
        .try_into()
        .map_err(|_| "hwbox: nonce Laenge falsch".to_string())?;
    let ct = B64
        .decode(box_json["box"].as_str().ok_or("hwbox: box fehlt")?)
        .map_err(|e| format!("hwbox box: {e}"))?;
    let aad = box_json["aad"].as_str().ok_or("hwbox: aad fehlt")?;
    let priv_key = p256::SecretKey::from_sec1_pem(pem).map_err(|e| format!("HW-PEM: {e}"))?;
    let shared = p256::ecdh::diffie_hellman(priv_key.to_nonzero_scalar(), ephem.as_affine());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&ephem_raw), shared.raw_secret_bytes())
        .expand(b"kv-m2-secretbox", &mut key)
        .map_err(|e| format!("HW-HKDF: {e}"))?;
    let aead = Aes256Gcm::new((&key).into());
    aead.decrypt(
        (&nonce).into(),
        Payload {
            msg: &ct,
            aad: aad.as_bytes(),
        },
    )
    .map_err(|_| "Hardwarekey passt nicht (Secretbox oeffnet nicht)".to_string())
}

#[cfg(feature = "test-login")]
fn hwbox_siegeln_v1(pub_pem: &str, inhalt: &[u8], aad: &str) -> Result<Value, String> {
    let pub_key = p256::SecretKey::from_sec1_pem(pub_pem)
        .map_err(|e| format!("HW-PEM: {e}"))?
        .public_key();
    let ephem = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let ephem_pub = ephem.public_key().to_encoded_point(false).as_bytes().to_vec();
    let ziel = pub_key;
    let shared = p256::ecdh::diffie_hellman(ephem.to_nonzero_scalar(), ziel.as_affine());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&ephem_pub), shared.raw_secret_bytes())
        .expand(b"kv-m2-secretbox", &mut key)
        .map_err(|e| format!("HW-HKDF: {e}"))?;
    let aead = Aes256Gcm::new((&key).into());
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = aead
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: inhalt,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| format!("HW-AES-GCM: {e}"))?;
    Ok(json!({
        "aad": aad,
        "algo": "ECIES-P256-HKDF-SHA256-AES256GCM",
        "box": B64.encode(ct),
        "ephem": B64.encode(ephem_pub),
        "nonce": B64.encode(nonce),
    }))
}

#[cfg(feature = "test-login")]
fn passbox_siegeln(passwort: &str, salt: &str, inhalt: &[u8], aad: &str) -> Result<Value, String> {
    let key = argon2_raw(passwort, salt)?;
    let aead = Aes256Gcm::new((&key).into());
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = aead
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: inhalt,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| format!("AES-GCM: {e}"))?;
    Ok(json!({
        "algo": "AES-256-GCM-Argon2id",
        "nonce": B64.encode(nonce),
        "box": B64.encode(ct),
        "aad": aad,
    }))
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

fn share(v: &Value, feld: &str) -> Result<(u8, Vec<u8>), String> {
    let s = &v[feld];
    let x = s["x"].as_u64().ok_or_else(|| format!("{feld}: x fehlt"))? as u8;
    let y = B64
        .decode(s["y"].as_str().ok_or_else(|| format!("{feld}: y fehlt"))?)
        .map_err(|e| format!("{feld} y: {e}"))?;
    Ok((x, y))
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
    pub master: Vec<u8>,
    pub space_addr: String,
    pub user_addr: String,
    pub username: String,
    pub passbox_payload: Value,
}

pub fn login_from_hashdatei(
    hash: &Value,
    space: &str,
    username: &str,
    password: &str,
    hw_pem: &str,
    salt: &str,
) -> Result<LoginOk, LoginError> {
    if hash["schema"].as_str() != Some("Argon2IDHashDatei/2") {
        return Err(LoginError::auth(
            "Hashdatei-Schema nicht unterstuetzt (erwartet /2)",
        ));
    }
    let space_addr = adresse(space, salt).map_err(|e| LoginError::auth(e))?;
    let user_addr = adresse(username, salt).map_err(|e| LoginError::auth(e))?;
    let entry = &hash["users"][format!("login:{user_addr}")];
    if entry.is_null() {
        return Err(LoginError::auth(
            "Username in diesem B2BSpace nicht gefunden",
        ));
    }
    let payload: Value = serde_json::from_slice(
        &passbox_oeffne(&entry["passbox"], password, salt)
            .map_err(|e| LoginError::auth(e))?,
    )
    .map_err(|e| LoginError::auth(format!("Passbox-Inhalt unlesbar: {e}")))?;
    let provider = share(&payload, "provider_shard").map_err(|e| LoginError::auth(e))?;
    let boxes = entry["hwboxes"]
        .as_array()
        .ok_or_else(|| LoginError::auth("hwboxes fehlen (ohne HW-Key keine Daten)"))?;
    let mut hw = None;
    let mut letzter = String::new();
    for bx in boxes {
        match hwbox_oeffne_v1(bx, hw_pem) {
            Ok(pt) => {
                let v: Value = serde_json::from_slice(&pt)
                    .map_err(|e| LoginError::auth(format!("HW-Box unlesbar: {e}")))?;
                hw = Some(share(&v, "hw_shard").map_err(|e| LoginError::auth(e))?);
                break;
            }
            Err(e) => letzter = e,
        }
    }
    let hw = hw.ok_or_else(|| {
        LoginError::auth(format!(
            "Kein Hardwarekey dieser Box passend ({} Boxen): {letzter}",
            boxes.len()
        ))
    })?;
    let master = combine2(provider, hw).map_err(|e| LoginError::auth(e))?;
    Ok(LoginOk {
        master,
        space_addr,
        user_addr,
        username: entry["username"].as_str().unwrap_or(username).to_string(),
        passbox_payload: payload,
    })
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
pub async fn s3_get_json(s3: &Value, rel_key: &str) -> Result<Value, LoginError> {
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
    serde_json::from_slice(&bytes)
        .map_err(|e| LoginError::auth(format!("Hashdatei kein JSON: {e}")))
}

/// Test-Welt (nur Feature `test-login`): Hashdatei + PEM + Passwort erzeugen.
#[cfg(feature = "test-login")]
pub fn build_test_world(passwort: &str, salt: &str, space: &str, username: &str) -> Value {
    use sha2::Digest;
    let master = {
        use rand::RngCore;
        let mut m = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut m);
        m
    };
    // Shamir 2-of-2 (x=1,2): y1=s^r, y2=s^r2 mit linearem Anteil.
    let mut r = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut r);
    }
    let y1: Vec<u8> = master.iter().zip(r.iter()).map(|(a, b)| a ^ b).collect();
    let y2: Vec<u8> = master
        .iter()
        .zip(r.iter())
        .map(|(a, b)| a ^ gf::mul(*b, 2))
        .collect();
    let provider = json!({"x": 1, "y": B64.encode(&y1)});
    let hwshard = json!({"x": 2, "y": B64.encode(&y2)});
    // PEM erzeugen (SEC1 wie setup_crypto::gen_pem).
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let der = secret.to_sec1_der().expect("SEC1");
    let params: [u8; 12] = [0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let content_len = der.len() - 2 + params.len();
    let mut voll = Vec::with_capacity(content_len + 2);
    voll.push(0x30);
    voll.push(content_len as u8);
    voll.extend_from_slice(&der[2..39]);
    voll.extend_from_slice(&params);
    voll.extend_from_slice(&der[39..]);
    let pem_b64 = B64.encode(&voll);
    let mut pem = String::from("-----BEGIN EC PRIVATE KEY-----\n");
    for chunk in pem_b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END EC PRIVATE KEY-----\n");
    let pass = passbox_siegeln(
        passwort,
        salt,
        &serde_json::to_vec(&json!({"provider_shard": provider, "username": username, "s3": {}, "buckets": ["demo"]})).unwrap(),
        "kv-login-passbox",
    )
    .expect("passbox");
    let hw = hwbox_siegeln_v1(&pem, &serde_json::to_vec(&json!({"hw_shard": hwshard})).unwrap(), "kv-hwbox")
        .expect("hwbox");
    let user_addr = adresse(username, salt).expect("adresse");
    let hash = json!({
        "schema": "Argon2IDHashDatei/2",
        "users": {
            format!("login:{user_addr}"): {
                "username": username,
                "passbox": pass,
                "hwboxes": [hw]
            }
        }
    });
    json!({
        "hashdatei": hash,
        "hw_pem": pem,
        "password": passwort,
        "salt": salt,
        "space": space,
        "username": username,
        "master_check_sha256": hex::encode(Sha256::digest(&master)),
    })
}

use wasm_bindgen::{JsCast, JsValue};
