//! WebAuthn/FIDO2-Einrichtung (Registrierung) im Setup.
//! Attestation-Format "none", ES256 (P-256). Keine externe WebAuthn-Lib.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde_json::{json, Value};
use sha2::Digest;

use super::webauthn_cbor::{decode, Cbor};

pub fn b64url(data: &[u8]) -> String {
    B64URL.encode(data)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    B64URL.decode(s.trim_end_matches('=')).map_err(|e| format!("b64url: {e}"))
}

pub struct AuthData {
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub sign_count: u32,
    pub credential: Option<(Vec<u8>, p256::PublicKey)>,
}

pub fn parse_auth_data(raw: &[u8]) -> Result<AuthData, String> {
    if raw.len() < 37 {
        return Err("authData zu kurz".into());
    }
    let flags = raw[32];
    let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);
    let mut credential = None;
    if flags & 0x40 != 0 {
        if raw.len() < 37 + 18 {
            return Err("authData: attested credential fehlt".into());
        }
        let mut p = 37 + 16;
        let cred_len = u16::from_be_bytes([raw[p], raw[p + 1]]) as usize;
        p += 2;
        if raw.len() < p + cred_len {
            return Err("authData: credentialId zu kurz".into());
        }
        let cred_id = raw[p..p + cred_len].to_vec();
        p += cred_len;
        let cose = decode(&raw[p..])?;
        let pubkey = cose_pubkey(&cose)?;
        credential = Some((cred_id, pubkey));
    }
    Ok(AuthData {
        rp_id_hash: raw[..32].to_vec(),
        flags,
        sign_count,
        credential,
    })
}

fn cose_pubkey(cose: &Cbor) -> Result<p256::PublicKey, String> {
    if cose.get_int(1) != Some(2) || cose.get_int(3) != Some(-7) || cose.get_int(-1) != Some(1) {
        return Err("COSE: nur EC2/P-256/ES256".into());
    }
    let xb = field(cose, -2)?;
    let yb = field(cose, -3)?;
    if xb.len() != 32 || yb.len() != 32 {
        return Err("COSE: x/y müssen 32 Byte sein".into());
    }
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&xb);
    sec1.extend_from_slice(&yb);
    p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| format!("COSE pubkey: {e}"))
}

/// COSE-Integer-Keys: -2/-3 liegen als NInt(1)/NInt(2) im Decoder.
fn field(cose: &Cbor, key: i64) -> Result<Vec<u8>, String> {
    match cose {
        Cbor::Map(entries) => {
            for (k, v) in entries {
                let kk = match k {
                    Cbor::UInt(u) => *u as i64,
                    Cbor::NInt(n) => *n,
                    _ => continue,
                };
                if kk == key {
                    return v.as_bytes().map(|b| b.to_vec()).ok_or("COSE: bytes erwartet".into());
                }
            }
            Err(format!("COSE: key {key} fehlt"))
        }
        _ => Err("COSE: map erwartet".into()),
    }
}

pub fn client_data_ok(
    raw: &[u8],
    typ: &str,
    challenge: &str,
    origin: &str,
) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| format!("clientDataJSON: {e}"))?;
    if v["type"] != json!(typ) {
        return Err(format!("clientData.type muss {typ} sein"));
    }
    if v["challenge"] != json!(challenge) {
        return Err("clientData.challenge falsch".into());
    }
    if v["origin"] != json!(origin) {
        return Err("clientData.origin falsch".into());
    }
    Ok(v)
}

/// Reine Registrierungsprüfung (ohne S3) — testbar mit Software-Authenticator.
pub fn verarbeite_registrierung(
    cd_b64: &str,
    att_b64: &str,
    challenge: &str,
    origin: &str,
    rp_id: &str,
    user: &str,
) -> Result<Value, String> {
    let cd = b64url_decode(cd_b64)?;
    client_data_ok(&cd, "webauthn.create", challenge, origin)?;
    let att = decode(&b64url_decode(att_b64)?)?;
    if att.get("fmt").and_then(|f| match f { Cbor::Text(t) => Some(t.as_str()), _ => None })
        != Some("none")
    {
        return Err("nur Attestation fmt=none".into());
    }
    let auth_raw = att.get("authData").and_then(|a| a.as_bytes()).ok_or("authData fehlt")?;
    let auth = parse_auth_data(auth_raw)?;
    if auth.rp_id_hash != sha2::Sha256::digest(rp_id.as_bytes()).to_vec() {
        return Err("rpIdHash falsch".into());
    }
    if auth.flags & 0x01 == 0 || auth.flags & 0x40 == 0 {
        return Err("flags: UP/AT fehlen".into());
    }
    let (cred_id, pubkey) = auth.credential.ok_or("credential fehlt")?;
    Ok(json!({
        "user": user,
        "credential_id": b64url(&cred_id),
        "pub_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pubkey.to_sec1_bytes()),
        "sign_count": auth.sign_count,
        "rp_id": rp_id,
        "created": chrono::Utc::now().to_rfc3339(),
    }))
}
