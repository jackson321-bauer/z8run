//! Schlüssel-Hülle + WAL-Versiegelung (AEAD) und Signatur (HMAC-Kette).
//!
//! KEIN neuer Krypto-Stack: aes-gcm/hkdf/hmac/sha2 sind bereits die
//! Primitive des Projekts (dieselbe Familie wie kette.rs/umschlag.rs).
//! Die Key-Hülle ist je DB eigen, wird beim Drop genullt und versucht
//! mlock (Sofort-Gesetz FEST 12).

use crate::dbnode::types::{DbError, DbResult};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// 32-Byte-Hülle je DB. Heap-allokiert, damit mlock/zeroize stabil sind.
pub struct KeyEnvelope {
    bytes: Box<[u8; 32]>,
}

impl KeyEnvelope {
    /// Leitet den DB-Schlüssel aus dem Masterkey ab (Master kommt von außen).
    pub fn derive(master: &[u8], db_id: &str) -> DbResult<Self> {
        if master.is_empty() {
            return Err(DbError::new("KEY", "Masterkey fehlt"));
        }
        let hk = Hkdf::<Sha256>::new(Some(b"z8-dbbox-db-key-v1"), master);
        let mut out = [0u8; 32];
        hk.expand(db_id.as_bytes(), &mut out)
            .map_err(|_| DbError::new("KEY", "HKDF expand fehlgeschlagen"))?;
        let bytes = Box::new(out);
        attempt_mlock(bytes.as_ptr(), bytes.len());
        out.zeroize();
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Nullt den Schlüsselspeicher (auch von Drop genutzt).
    pub fn wipe(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for KeyEnvelope {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(unix)]
fn attempt_mlock(ptr: *const u8, len: usize) {
    extern "C" {
        fn mlock(addr: *const std::os::raw::c_void, len: usize) -> std::os::raw::c_int;
    }
    // mlock ist ein VERSUCH (Rlimit/Festplatten-Swap möglich); Fehler sind ok.
    unsafe {
        let _ = mlock(ptr as *const std::os::raw::c_void, len);
    }
}

#[cfg(not(unix))]
fn attempt_mlock(_ptr: *const u8, _len: usize) {}

fn subkey(key: &KeyEnvelope, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"z8-dbbox-wal-v1"), key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf wal subkey");
    out
}

fn aad_bytes(db_id: &str, nr: u64, prev_hash: &str) -> Vec<u8> {
    format!("{db_id}|{nr}|{prev_hash}").into_bytes()
}

/// Versiegelt WAL-Klartext: nonce(12) || ciphertext+tag || hmac(32).
pub fn seal(
    key: &KeyEnvelope,
    db_id: &str,
    nr: u64,
    prev_hash: &str,
    plaintext: &[u8],
) -> DbResult<Vec<u8>> {
    let enc = subkey(key, b"enc");
    let mac_key = subkey(key, b"mac");
    let cipher = Aes256Gcm::new((&enc).into());
    let nonce: [u8; 12] = rand::random();
    let aad = aad_bytes(db_id, nr, prev_hash);
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DbError::new("SEAL", "AES-GCM Versiegelung fehlgeschlagen"))?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("hmac key");
    mac.update(&aad);
    mac.update(&nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();
    let mut out = Vec::with_capacity(12 + ct.len() + 32);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Öffnet eine versiegelte WAL-Nutzlast und prüft die HMAC-Signatur.
pub fn open(
    key: &KeyEnvelope,
    db_id: &str,
    nr: u64,
    prev_hash: &str,
    sealed: &[u8],
) -> DbResult<Vec<u8>> {
    if sealed.len() < 12 + 16 + 32 {
        return Err(DbError::new("SEAL", "WAL-Nutzlast zu kurz"));
    }
    let (nonce_b, rest) = sealed.split_at(12);
    let (ct, tag) = rest.split_at(rest.len() - 32);
    let enc = subkey(key, b"enc");
    let mac_key = subkey(key, b"mac");
    let aad = aad_bytes(db_id, nr, prev_hash);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("hmac key");
    mac.update(&aad);
    mac.update(nonce_b);
    mac.update(ct);
    mac.verify_slice(tag)
        .map_err(|_| DbError::new("SIGNATUR", "WAL-Signatur ungültig"))?;
    let cipher = Aes256Gcm::new((&enc).into());
    let nonce: [u8; 12] = nonce_b.try_into().expect("nonce len");
    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ct,
                aad: &aad,
            },
        )
        .map_err(|_| DbError::new("SEAL", "WAL entsiegeln fehlgeschlagen"))
}

/// SHA256-Hex über kanonisch zusammengesetzte WAL-Kopfdaten.
pub fn wal_hash(nr: u64, prev_hash: &str, db_id: &str, seal_b64: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{nr}|{prev_hash}|{db_id}|{seal_b64}").as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_envelope_wird_bei_wipe_genullt() {
        let mut env = KeyEnvelope::derive(b"master", "db1").unwrap();
        assert!(env.as_bytes().iter().any(|b| *b != 0), "Kennzeichen-Byte");
        let ptr = env.as_bytes().as_ptr() as *const [u8; 32];
        env.wipe();
        let view: &[u8; 32] = unsafe { &*ptr };
        assert!(view.iter().all(|b| *b == 0), "Key-Speicher nicht genullt");
    }

    #[test]
    fn wal_seal_roundtrip_und_signatur_erkennt_manipulation() {
        let env = KeyEnvelope::derive(b"master", "db1").unwrap();
        let sealed = seal(&env, "db1", 1, "", b"hallo").unwrap();
        assert_eq!(open(&env, "db1", 1, "", &sealed).unwrap(), b"hallo");
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert_eq!(open(&env, "db1", 1, "", &bad).unwrap_err().code, "SIGNATUR");
    }
}
