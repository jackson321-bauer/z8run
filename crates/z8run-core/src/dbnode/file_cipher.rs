//! File-Cipher fuer SQLite-Dateien (Weg A, FEST 25): SQLite selbst laeuft
//! PLAIN; die Verschluesselung sitzt in UNSERER Schicht. Dieselbe Datei-
//! form gilt nativ und im Browser (pure Rust AES-256-GCM/HKDF).
//!
//! Format: `Z8FC1` || u32 part_size || [u32 ct_len || nonce(12) || ct]*.
//! Part-Key = HKDF-SHA256(DB-Key, Salt `z8-file-cipher-v1`, Info = part).
//! AAD bindet Datei-Magic + Part-Index; Reihenfolge/Tausch = Fehler.

use crate::dbnode::types::{DbError, DbResult};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::path::Path;

pub const MAGIC: &[u8; 5] = b"Z8FC1";
pub const PART: usize = 1024 * 1024;

fn part_key(key: &[u8], part: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"z8-file-cipher-v1"), key);
    let mut out = [0u8; 32];
    hk.expand(&part.to_be_bytes(), &mut out)
        .expect("HKDF-Expand 32 Byte");
    out
}

fn aad(part: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(9);
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(&part.to_be_bytes());
    a
}

pub fn is_cipher_file(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 5];
    f.read_exact(&mut head).is_ok() && &head == MAGIC
}

/// Versiegelt Klartext-Bytes (part-weise) in die File-Cipher-Form.
pub fn seal_bytes(key: &[u8], plain: &[u8]) -> DbResult<Vec<u8>> {
    let mut out = Vec::with_capacity(plain.len() + 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(PART as u32).to_be_bytes());
    for (i, chunk) in plain.chunks(PART).enumerate() {
        let part = i as u32;
        let cipher = Aes256Gcm::new_from_slice(&part_key(key, part))
            .map_err(|_| DbError::new("FILECIPHER", "Key ungueltig"))?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &aad(part),
                },
            )
            .map_err(|_| DbError::new("FILECIPHER", "AES-GCM fehlgeschlagen"))?;
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// Oeffnet eine File-Cipher-Datei; falscher Key/Manipulation = Fehler.
pub fn open_bytes(key: &[u8], sealed: &[u8]) -> DbResult<Vec<u8>> {
    if sealed.len() < 9 || &sealed[..5] != MAGIC {
        return Err(DbError::new("FILECIPHER", "kein Z8FC1-Container"));
    }
    let part_size = u32::from_be_bytes(sealed[5..9].try_into().unwrap()) as usize;
    if part_size == 0 || part_size > 64 * 1024 * 1024 {
        return Err(DbError::new("FILECIPHER", "Part-Groesse ungueltig"));
    }
    let mut out = Vec::new();
    let mut pos = 9usize;
    let mut part = 0u32;
    while pos < sealed.len() {
        if pos + 4 + 12 > sealed.len() {
            return Err(DbError::new("FILECIPHER", "abgeschnittener Part"));
        }
        let len = u32::from_be_bytes(sealed[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if len < 16 || pos + 12 + len > sealed.len() {
            return Err(DbError::new("FILECIPHER", "Part-Laenge ungueltig"));
        }
        let nonce = &sealed[pos..pos + 12];
        pos += 12;
        let ct = &sealed[pos..pos + len];
        pos += len;
        if len - 16 > part_size {
            return Err(DbError::new("FILECIPHER", "Part zu gross"));
        }
        let cipher = Aes256Gcm::new_from_slice(&part_key(key, part))
            .map_err(|_| DbError::new("FILECIPHER", "Key ungueltig"))?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad(part),
                },
            )
            .map_err(|_| DbError::new("FILECIPHER", "Key/Integritaet falsch"))?;
        out.extend_from_slice(&plain);
        part += 1;
    }
    Ok(out)
}

pub fn read_encrypted(path: &Path, key: &[u8]) -> DbResult<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(sealed) => open_bytes(key, &sealed).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(DbError::new("FILECIPHER", format!("read: {e}"))),
    }
}

pub fn write_encrypted(path: &Path, key: &[u8], plain: &[u8]) -> DbResult<()> {
    let sealed = seal_bytes(key, plain)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| DbError::new("FILECIPHER", format!("mkdir: {e}")))?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, &sealed)
        .map_err(|e| DbError::new("FILECIPHER", format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| DbError::new("FILECIPHER", format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datei_ist_chiffre_und_key_gebunden() {
        let key = [7u8; 32];
        let plain = b"SQLite format 3\0".to_vec();
        let sealed = seal_bytes(&key, &plain).unwrap();
        assert_eq!(&sealed[..5], MAGIC);
        assert!(!sealed.windows(15).any(|w| w == b"SQLite format 3"));
        assert_eq!(open_bytes(&key, &sealed).unwrap(), plain);
        assert!(open_bytes(&[8u8; 32], &sealed).is_err());
    }

    #[test]
    fn mehrere_parts_roundtrip() {
        let key = [9u8; 32];
        let mut plain = vec![0u8; PART * 2 + 17];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let sealed = seal_bytes(&key, &plain).unwrap();
        assert_eq!(open_bytes(&key, &sealed).unwrap(), plain);
    }
}
