//! Argon2IDHashDatei/3 im Browser: b2b/{addr}.txt + workspaces/{addr}/
//! hw-shards.txt, Passbox + HW-Box (v3 hybrid via EINE umschlag.rs-Quelle).

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::login::{self, LoginOk};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn sha_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn salt_space(space: &str) -> String {
    sha_hex(format!("kv3-salt:{space}").as_bytes())
}

pub fn salt_user(space_salt: &str, name: &str) -> String {
    sha_hex(format!("{space_salt}:user:{name}").as_bytes())
}

pub fn user_addr(space: &str, name: &str) -> Result<String, String> {
    let su = salt_user(&salt_space(space), name);
    login::adresse(name, &su)
}

/// Zerlegt das /3-Textformat in (Adresse→Block, Block→Chiffre).
pub fn parse(text: &str) -> Result<(Vec<(String, String)>, Vec<(String, String)>), String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    if lines.first().copied() != Some("Argon2IDHashDatei/3") {
        return Err("kein Argon2IDHashDatei/3-Kopf".into());
    }
    let pos = |marker: &str, from: usize| {
        lines
            .iter()
            .enumerate()
            .skip(from)
            .find(|(_, l)| **l == marker)
            .map(|(i, _)| i)
    };
    let sb = pos("Secretboxes", 0).ok_or("Secretboxes fehlt")?;
    let sb_a = pos("Anfang", sb).ok_or("Secretboxes/Anfang fehlt")?;
    let sb_e = pos("Ende", sb_a).ok_or("Secretboxes/Ende fehlt")?;
    let en = pos("Encrypted", sb_e).ok_or("Encrypted fehlt")?;
    let en_a = pos("Anfang", en).ok_or("Encrypted/Anfang fehlt")?;
    let en_e = pos("Ende", en_a).ok_or("Encrypted/Ende fehlt")?;
    let mut addrs = Vec::new();
    for l in &lines[sb_a + 1..sb_e] {
        if l.is_empty() {
            continue;
        }
        let (a, b) = l
            .split_once(" = ")
            .or_else(|| l.rsplit_once('='))
            .ok_or_else(|| format!("Adresszeile: {l}"))?;
        addrs.push((a.trim().to_string(), b.trim().to_string()));
    }
    let mut blocks = Vec::new();
    let mut it = lines[en_a + 1..en_e].iter().filter(|l| !l.is_empty());
    while let Some(name) = it.next() {
        let cipher = it.next().ok_or("Block ohne Chiffre")?;
        blocks.push((name.trim().to_string(), cipher.trim().to_string()));
    }
    Ok((addrs, blocks))
}

fn box_aus(text: &str) -> Result<Value, String> {
    let raw = B64.decode(text.trim()).map_err(|e| format!("box b64: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("box json: {e}"))
}

fn share(v: &Value, feld: &str) -> Result<(u8, Vec<u8>), String> {
    let s = &v[feld];
    let x = s["x"].as_u64().ok_or_else(|| format!("{feld}: x fehlt"))? as u8;
    let y_text = s["y_b64"]
        .as_str()
        .or_else(|| s["y"].as_str())
        .ok_or_else(|| format!("{feld}: y fehlt"))?;
    let y = B64
        .decode(y_text)
        .map_err(|e| format!("{feld} y: {e}"))?;
    Ok((x, y))
}

pub fn pem_pub_b64(pem: &str) -> Result<String, String> {
    let secret = p256::SecretKey::from_sec1_pem(pem).map_err(|e| format!("PEM: {e}"))?;
    Ok(B64.encode(
        p256::PublicKey::from(secret.public_key()).to_sec1_bytes(),
    ))
}

/// Öffnet NUR den HW-Shard (Faktor 2) lokal — für den nativen WebAuthn-Weg.
/// Der Server sieht später nur `{x, y_b64}`, nie PEM oder KEM-Privatekey.
pub fn open_shard_v3(hw_shards: &str, hw_pem: &str, kem_dk_b64: &str) -> Result<Value, String> {
    let kem_dk = B64
        .decode(kem_dk_b64.trim())
        .map_err(|e| format!("ML-KEM-Privatekey (Base64): {e}"))?;
    let (ha, hb) = parse(hw_shards)?;
    let pub_b64 = pem_pub_b64(hw_pem)?;
    let hblock = ha
        .iter()
        .find(|(a, _)| a == &pub_b64)
        .map(|(_, b)| b.clone())
        .ok_or("Kein Hardwarekey dieser Box passend")?;
    let hcipher = hb
        .iter()
        .find(|(b, _)| b == &hblock)
        .map(|(_, c)| c.clone())
        .ok_or("HW-Chiffre fehlt")?;
    let hbox = box_aus(&hcipher)?;
    let priv_key = p256::SecretKey::from_sec1_pem(hw_pem).map_err(|e| format!("HW-PEM: {e}"))?;
    let plain = crate::umschlag::oeffnen(&hbox, &priv_key, &kem_dk)
        .map_err(|e| format!("HW-Box: {e}"))?;
    let hval: Value = serde_json::from_slice(&plain).map_err(|e| format!("HW-Inhalt: {e}"))?;
    let (x, y) = share(&hval, "shamir_hw")?;
    Ok(serde_json::json!({ "x": x, "y_b64": B64.encode(y), "pub_b64": pub_b64 }))
}

#[allow(clippy::too_many_arguments)]
pub fn login_v3(
    b2b: &str,
    hw_shards: &str,
    space: &str,
    username: &str,
    password: &str,
    hw_pem: &str,
    kem_dk_b64: &str,
) -> Result<LoginOk, String> {
    let kem_dk = B64
        .decode(kem_dk_b64.trim())
        .map_err(|e| format!("ML-KEM-Privatekey (Base64): {e}"))?;
    let space_salt = salt_space(space);
    let su = salt_user(&space_salt, username);
    let user_addr = login::adresse(username, &su)?;
    let (addrs, blocks) = parse(b2b)?;
    let block = addrs
        .iter()
        .find(|(a, _)| a == &user_addr)
        .map(|(_, b)| b.clone())
        .ok_or("Username in diesem Space nicht gefunden")?;
    let cipher = blocks
        .iter()
        .find(|(b, _)| b == &block)
        .map(|(_, c)| c.clone())
        .ok_or("Block-Chiffre fehlt")?;
    let passbox = box_aus(&cipher)?;
    let payload: Value = serde_json::from_slice(
        &login::passbox_oeffne(&passbox, password, &su)?,
    )
    .map_err(|e| format!("Passbox-Inhalt unlesbar: {e}"))?;
    let provider = share(&payload, "shamir_provider")?;

    let (ha, hb) = parse(hw_shards)?;
    let pub_b64 = pem_pub_b64(hw_pem)?;
    let hblock = ha
        .iter()
        .find(|(a, _)| a == &pub_b64)
        .map(|(_, b)| b.clone())
        .ok_or("Kein Hardwarekey dieser Box passend")?;
    let hcipher = hb
        .iter()
        .find(|(b, _)| b == &hblock)
        .map(|(_, c)| c.clone())
        .ok_or("HW-Chiffre fehlt")?;
    let hbox = box_aus(&hcipher)?;
    let priv_key = p256::SecretKey::from_sec1_pem(hw_pem).map_err(|e| format!("HW-PEM: {e}"))?;
    let plain = crate::umschlag::oeffnen(&hbox, &priv_key, &kem_dk)
        .map_err(|e| format!("HW-Box: {e}"))?;
    let hval: Value = serde_json::from_slice(&plain).map_err(|e| format!("HW-Inhalt: {e}"))?;
    let hw = share(&hval, "shamir_hw")?;
    let master = login::combine2(provider, hw)?;
    let space_addr = login::adresse(space, &space_salt)?;
    Ok(LoginOk {
        master: Zeroizing::new(master),
        space_addr,
        user_addr,
        username: username.to_string(),
        passbox_payload: payload,
    })
}
