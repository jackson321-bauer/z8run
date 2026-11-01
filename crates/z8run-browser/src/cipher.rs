//! Z8FC1-File-Cipher im Browser (dieselbe Form/Algorithmus wie nativ).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

const MAGIC: &[u8; 5] = b"Z8FC1";
const PART: usize = 1024 * 1024;

fn part_key(key: &[u8], part: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"z8-file-cipher-v1"), key);
    let mut out = [0u8; 32];
    hk.expand(&part.to_be_bytes(), &mut out).expect("hkdf");
    out
}

fn aad(part: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(9);
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(&part.to_be_bytes());
    a
}

pub fn seal(key: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plain.len() + 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(PART as u32).to_be_bytes());
    for (i, chunk) in plain.chunks(PART).enumerate() {
        let part = i as u32;
        let cipher = Aes256Gcm::new_from_slice(&part_key(key, part)).expect("key");
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: chunk, aad: &aad(part) },
            )
            .expect("aes-gcm");
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
    }
    out
}

pub fn open(key: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 9 || &sealed[..5] != MAGIC {
        return Err("kein Z8FC1-Container".into());
    }
    let mut out = Vec::new();
    let mut pos = 9usize;
    let mut part = 0u32;
    while pos < sealed.len() {
        if pos + 16 > sealed.len() {
            return Err("abgeschnittener Part".into());
        }
        let len = u32::from_be_bytes(sealed[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if len < 16 || pos + 12 + len > sealed.len() {
            return Err("Part-Laenge ungueltig".into());
        }
        let nonce = &sealed[pos..pos + 12];
        pos += 12;
        let ct = &sealed[pos..pos + len];
        pos += len;
        let cipher = Aes256Gcm::new_from_slice(&part_key(key, part)).map_err(|e| e.to_string())?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload { msg: ct, aad: &aad(part) },
            )
            .map_err(|_| "Key/Integritaet falsch".to_string())?;
        out.extend_from_slice(&plain);
        part += 1;
    }
    Ok(out)
}
