//! Part-Krypto (AES-256-GCM, HKDF je Part) + Key-Hülle + Upload-Schleife.
//! KEIN neuer Krypto-Stack: dieselben Primitive wie crypto.rs.

use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::DbHandle;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::io::Read;

pub const BLOB_PART_SIZE: usize = 1024 * 1024;

pub fn part_key(db: &str, blob_id: &str, part: u64) -> String {
    format!("blobs/{db}/{blob_id}/{part:08}.part")
}

pub fn blob_prefix(db: &str) -> String {
    format!("blobs/{db}/")
}

pub(crate) fn derive(key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"z8-blob-part-v1"), key);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf blob-part");
    out
}

pub fn encrypt_part(key: &[u8; 32], aad_ctx: &str, part: u64, plain: &[u8]) -> DbResult<Vec<u8>> {
    let info = format!("{aad_ctx}|p{part}");
    let sub = derive(key, info.as_bytes());
    let cipher = Aes256Gcm::new((&sub).into());
    let nonce: [u8; 12] = rand::random();
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: plain, aad: info.as_bytes() })
        .map_err(|_| DbError::new("BLOB_SEAL", "Part-Verschlüsselung fehlgeschlagen"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_part(key: &[u8; 32], aad_ctx: &str, part: u64, sealed: &[u8]) -> DbResult<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return Err(DbError::new("BLOB_SEAL", "Part zu kurz"));
    }
    let info = format!("{aad_ctx}|p{part}");
    let (nonce_b, ct) = sealed.split_at(12);
    let sub = derive(key, info.as_bytes());
    let cipher = Aes256Gcm::new((&sub).into());
    let nonce: [u8; 12] = nonce_b.try_into().expect("nonce len");
    cipher
        .decrypt((&nonce).into(), Payload { msg: ct, aad: info.as_bytes() })
        .map_err(|_| DbError::new("BLOB_SEAL", "Part entsiegeln fehlgeschlagen (Key/AAD)"))
}

pub fn seal_db_key(h: &DbHandle, id: &str, key: &[u8; 32]) -> DbResult<String> {
    let hk = Hkdf::<Sha256>::new(Some(b"z8-blob-key-wrap-v1"), h.key.as_bytes());
    let mut sub = [0u8; 32];
    hk.expand(id.as_bytes(), &mut sub).expect("hkdf blob key");
    let cipher = Aes256Gcm::new((&sub).into());
    let nonce: [u8; 12] = rand::random();
    let aad = format!("z8-blob-key|{id}");
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: key, aad: aad.as_bytes() })
        .map_err(|_| DbError::new("BLOB_KEY", "Key-Hülle versiegeln fehlgeschlagen"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

pub fn open_db_key(h: &DbHandle, id: &str, b64: &str) -> DbResult<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| DbError::new("BLOB_KEY", format!("Key-Hülle Base64: {e}")))?;
    if raw.len() < 12 + 16 {
        return Err(DbError::new("BLOB_KEY", "Key-Hülle zu kurz"));
    }
    let (nonce_b, ct) = raw.split_at(12);
    let hk = Hkdf::<Sha256>::new(Some(b"z8-blob-key-wrap-v1"), h.key.as_bytes());
    let mut sub = [0u8; 32];
    hk.expand(id.as_bytes(), &mut sub).expect("hkdf blob key");
    let cipher = Aes256Gcm::new((&sub).into());
    let nonce: [u8; 12] = nonce_b.try_into().expect("nonce len");
    let aad = format!("z8-blob-key|{id}");
    let plain = cipher
        .decrypt((&nonce).into(), Payload { msg: ct, aad: aad.as_bytes() })
        .map_err(|_| DbError::new("BLOB_KEY", "Key-Hülle öffnet nicht (Masterkey?)"))?;
    plain
        .as_slice()
        .try_into()
        .map_err(|_| DbError::new("BLOB_KEY", "Content-Key-Länge falsch"))
}

pub(crate) async fn upload_parts<R: Read>(
    h: &DbHandle, blob_id: &str, key: &[u8; 32], aad_ctx: &str, reader: &mut R,
) -> DbResult<(u64, u64, String)> {
    let mut buf = vec![0u8; BLOB_PART_SIZE];
    let mut sha = Sha256::new();
    let mut size = 0u64;
    let mut parts = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| DbError::new("BLOB_INPUT", format!("lesen: {e}")))?;
        if n == 0 && parts > 0 {
            break;
        }
        sha.update(&buf[..n]);
        size += n as u64;
        let ct = encrypt_part(key, aad_ctx, parts, &buf[..n])?;
        h.storage.write(&part_key(&h.id, blob_id, parts), &ct).await?;
        parts += 1;
        if n < BLOB_PART_SIZE {
            break;
        }
    }
    Ok((parts, size, hex::encode(sha.finalize())))
}
