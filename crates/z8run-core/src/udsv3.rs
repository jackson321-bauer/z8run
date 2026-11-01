//! UDSV3: E2E-verschluesselte Frames auf internen Unix-Domain-Sockets.
//!
//! Frame: `[u32 len][u64 counter][u32 ct_len][ciphertext]` (alle Zahlen BE,
//! `len` zaehlt ab counter). Schluessel = HKDF-SHA256(Transport-Master,
//! Salt `z8-udsv3`, Info = Socket-Kontext). Nonce = 4 Nullbytes + Counter;
//! AAD = Kontext + Counter. Jede Richtung fuehrt einen eigenen Counter;
//! ein Frame mit falschem/altem Counter wird abgewiesen (Replay-Schutz).
//! Der Transport-Master liegt NIE im Repo: Env `Z8_UDSV3_MASTER` oder die
//! Key-Datei `Z8_UDSV3_KEYFILE` (Default `/data/z8run/udsv3.key`, 0600).

use std::io;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Obergrenze eines Frames (Payload). Der dbnode-Kanal erlaubt 32 MiB
/// Kommandos; alles darueber ist ein Protokollfehler.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;
pub const HEADER: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Nur udsv3-Frames; Klartext = Verbindung abgewiesen.
    Strict,
    /// Debug-Fallback: Klartext erlaubt, aber mit Meta-Ereignis im Log.
    DebugPlain,
}

impl Mode {
    pub fn from_env() -> Self {
        match std::env::var("Z8_UDSV3").unwrap_or_default().as_str() {
            "off" | "debug" | "plain" => Mode::DebugPlain,
            _ => Mode::Strict,
        }
    }

    pub fn is_strict(self) -> bool {
        self == Mode::Strict
    }
}

/// Meldet einen Klartext-Downgrade als Meta-Ereignis (JSONL, maschinenlesbar).
pub fn meta_downgrade(context: &str) {
    tracing::warn!(
        meta = true,
        action = "udsv3_downgrade",
        socket_kontext = context,
        status = "debug",
        "udsv3: Klartext-Downgrade im Debug-Modus akzeptiert"
    );
}

/// Transport-Master aus Env oder Key-Datei; fehlt sie, wird sie erzeugt.
pub fn master_from_env() -> io::Result<Vec<u8>> {
    if let Ok(raw) = std::env::var("Z8_UDSV3_MASTER") {
        if !raw.trim().is_empty() {
            return decode_master(raw.trim())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Z8_UDSV3_MASTER ungueltig"));
        }
    }
    let path = std::env::var("Z8_UDSV3_KEYFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/data/z8run/udsv3.key"));
    load_or_create_master(&path)
}

/// Liest die Key-Datei (roh 32 Byte oder Hex/Base64) oder legt sie an.
pub fn load_or_create_master(path: &Path) -> io::Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if let Some(key) = decode_master_bytes(&bytes) {
                return Ok(key);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} enthaelt keinen gueltigen Master", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Rennen zwischen zwei Prozessen: create_new entscheidet, wer schreibt;
    // der Verlierer liest nach dem atomaren Schreiben.
    for _ in 0..200 {
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
        {
            Ok(mut f) => {
                use std::io::Write;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                let mut key = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut key);
                f.write_all(&key)?;
                f.sync_all()?;
                return Ok(key);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if let Ok(bytes) = std::fs::read(path) {
                    if let Some(key) = decode_master_bytes(&bytes) {
                        return Ok(key);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("{} wurde nicht rechtzeitig lesbar", path.display()),
    ))
}

fn decode_master(raw: &str) -> Option<Vec<u8>> {
    decode_master_bytes(raw.as_bytes())
}

fn decode_master_bytes(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() == 32 {
        return Some(raw.to_vec());
    }
    let text = std::str::from_utf8(raw).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    let hexs = text.strip_prefix("0x").unwrap_or(text);
    if hexs.len() == 64 && hexs.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v) = hex::decode(hexs) {
            if v.len() == 32 {
                return Some(v);
            }
        }
    }
    use base64::Engine as _;
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(v) = engine.decode(text) {
            if v.len() == 32 {
                return Some(v);
            }
        }
    }
    if text.len() >= 16 {
        return Some(text.as_bytes().to_vec());
    }
    None
}

/// Schluessel fuer einen Socket-Kontext (z.B. "admin", "dbnode-msg", "login").
pub fn transport_key(master: &[u8], context: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"z8-udsv3"), master);
    let mut key = [0u8; 32];
    let info = format!("udsv3|{context}");
    hk.expand(info.as_bytes(), &mut key)
        .expect("HKDF-Expand fuer 32 Byte kann nicht scheitern");
    key
}

fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn aad(context: &str, counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(context.len() + 8);
    aad.extend_from_slice(context.as_bytes());
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

/// Versiegelt einen Klartext in EINEN udsv3-Frame (inkl. Laengenkopf).
pub fn seal_frame(key: &[u8; 32], context: &str, counter: u64, plain: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-Byte-Key");
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_for(counter)),
            Payload {
                msg: plain,
                aad: &aad(context, counter),
            },
        )
        .expect("AES-GCM-Verschluesselung");
    let total = 8 + 4 + ct.len();
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Oeffnet einen Frame-Koerper (ohne 4-Byte-Laengenkopf) mit Counter-Pruefung.
pub fn open_frame(
    key: &[u8; 32],
    context: &str,
    expected: u64,
    body: &[u8],
) -> io::Result<Vec<u8>> {
    if body.len() < HEADER {
        return Err(proto("Frame zu kurz"));
    }
    let counter = u64::from_be_bytes(body[0..8].try_into().unwrap());
    let ct_len = u32::from_be_bytes(body[8..12].try_into().unwrap()) as usize;
    if ct_len != body.len() - 12 || ct_len > MAX_FRAME {
        return Err(proto("Frame-Laenge ungueltig"));
    }
    if counter != expected {
        return Err(proto(&format!(
            "Replay/Counter: erwartet {expected}, bekam {counter}"
        )));
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-Byte-Key");
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_for(counter)),
            Payload {
                msg: &body[12..],
                aad: &aad(context, counter),
            },
        )
        .map_err(|_| proto("Entschluesselung/Integritaet fehlgeschlagen"))
}

fn proto(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("udsv3: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_ist_chiffre_und_counter_gebunden() {
        let key = transport_key(b"0123456789abcdef0123456789abcdef", "admin");
        let plain = br#"POST /v1/status HTTP/1.1 Host: localhost"#;
        let frame = seal_frame(&key, "admin", 7, plain);
        assert_ne!(&frame[16..], plain.as_slice(), "Payload muss Chiffre sein");
        let body = &frame[4..];
        let open = open_frame(&key, "admin", 7, body).unwrap();
        assert_eq!(open, plain);
        // Replay desselben Frames: Counter 7 != erwartet 8 -> abgewiesen.
        assert!(open_frame(&key, "admin", 8, body).is_err());
        // Falscher Kontext -> Integritaet/AAD schlaegt fehl.
        let other = transport_key(b"0123456789abcdef0123456789abcdef", "dbnode-msg");
        assert!(open_frame(&other, "admin", 7, body).is_err());
    }

    #[test]
    fn master_datei_wird_0600_erzeugt_und_wieder_geladen() {
        let dir = std::env::temp_dir().join(format!("udsv3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("udsv3.key");
        let _ = std::fs::remove_file(&path);
        let a = load_or_create_master(&path).unwrap();
        assert_eq!(a.len(), 32);
        let b = load_or_create_master(&path).unwrap();
        assert_eq!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
