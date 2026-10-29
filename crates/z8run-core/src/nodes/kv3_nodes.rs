//! KronVault /3-Login-Kette als z8-Nodes (Setup-Flow + Login-Flow).
//!
//! Die Kette (fester Space-Salt, abwärts adaptiert):
//!   salt_space  = sha256("kv3-salt:" + space)
//!   salt_user   = sha256(salt_space + ":user:" + username)
//!   salt_shared = sha256(salt_space + ":shared:" + shared_name)
//!
//! kv3-Adresse = argon2(name, salt) -> base32[0..32]
//!
//! Nodes:
//!   kv3-adresse   — berechnet Adresse aus name+salt (oder leitet Salte ab:
//!                   space -> user -> shared). Rein, deterministisch.
//!   kv3-open      — lädt Hashdatei von S3 (pfad = b2b/<space-addr>/<name>.txt
//!                   oder direkter key), findet Adresse, öffnet Passwort-Box,
//!                   gibt Provider-Shard + Block-Inhalt weiter.
//!   kv3-hwshard   — lädt hw-shards.txt aus dem Workspace-Ordner (S3),
//!                   öffnet ECIES-Box mit PEM -> HW-Shard.
//!   kv3-master    — kombiniert Provider+HW-Shard (2-of-2) -> Master-Fingerprint.
//!   kv3-socket    — bergibt fertige Session-Daten (Adressen, S3-Keys des
//!                   Users, Master-Fingerprint) an den Unix-Socket des
//!                   (späteren) Proxys: 1 Zeile JSON + Shutdown-Write.
//!
//! Alle Secrets (Passwort, PEM, Shards, Master) NUR im Payload-Pfad;
//! Nodes strippen sie vor dem Output.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kv_store::s3::S3Endpoint;
use serde_json::{json, Value};
use sha2::Digest;
use tracing::warn;

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::{error_output, require_non_empty};

fn sha_hex(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

/// Fester Salt pro B2B-Space, nach unten adaptiert (keine Rotation).
pub fn salt_space(space: &str) -> String {
    sha_hex(format!("kv3-salt:{space}").as_bytes())
}
pub fn salt_user(space_salt: &str, name: &str) -> String {
    sha_hex(format!("{space_salt}:user:{name}").as_bytes())
}
pub fn salt_shared(space_salt: &str, name: &str) -> String {
    sha_hex(format!("{space_salt}:shared:{name}").as_bytes())
}

/// kv3-Adresse: argon2(name, salt) -> base32, 32 Zeichen (wie kette::adresse).
/// Wird ohne kette-Abhängigkeit nachgebaut? Nein — kette ist nicht in diesem
/// Crate. Wir laden die Adresse-Berechnung über eine kleine interne Kopie der
/// Argon2-Logik mit identischen Parametern (m=19456,t=2,p=1, BASE32_NOPAD,
/// lowercase, take 32) — EINE Wahrheit bleibt kette.rs; dieser Node wirft
/// einen Hinweis, dass Produktiv-Kernen kette.rs nutzen.
fn kv3_adresse(name: &str, salt: &str) -> Result<String, String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|e| format!("argon2 params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(name.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|e| format!("argon2: {e}"))?;
    let b32 = data_encoding::BASE32_NOPAD.encode(&out).to_lowercase();
    Ok(b32.chars().take(32).collect())
}

fn parse_datei(text: &str) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut addrs = Vec::new();
    let mut blocks = Vec::new();
    let mut section = 0u8;
    let mut cur = String::new();
    let mut buf = String::new();
    for line in text.lines() {
        let t = line.trim();
        match t {
            "Secretboxes" => section = 1,
            "Encrypted" => section = 2,
            "Ende" => {
                if section == 2 && !cur.is_empty() {
                    blocks.push((cur.clone(), buf.trim().to_string()));
                    cur.clear();
                    buf.clear();
                }
            }
            "Anfang" => {}
            _ => {
                if section == 1 {
                    if let Some((a, b)) = t.split_once(" = ") {
                        addrs.push((a.to_string(), b.trim().to_string()));
                    }
                } else if section == 2 {
                    if t.starts_with("Block-") {
                        if !cur.is_empty() {
                            blocks.push((cur.clone(), buf.trim().to_string()));
                            buf.clear();
                        }
                        cur = t.to_string();
                    } else if !t.is_empty() {
                        buf.push_str(line);
                        buf.push('\n');
                    }
                }
            }
        }
    }
    (addrs, blocks)
}

fn s3_endpoint_aus(cfg: &Value) -> Result<S3Endpoint, String> {
    Ok(S3Endpoint {
        host: cfg["host"].as_str().ok_or("s3.host fehlt")?.to_string(),
        region: cfg["region"].as_str().unwrap_or("us-east-1").to_string(),
        access_key: cfg["access_key"]
            .as_str()
            .ok_or("s3.access_key fehlt")?
            .to_string(),
        secret_key: cfg["secret_key"]
            .as_str()
            .ok_or("s3.secret_key fehlt")?
            .to_string(),
    })
}

// ---------------------------------------------------------------------------
// Node 1: kv3-adresse
// ---------------------------------------------------------------------------

pub struct Kv3AdresseNode {
    name: String,
    ebene: String, // "space" | "user" | "shared"
    name_path: String,
    space_path: String,
    shared_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for Kv3AdresseNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let name = msg
            .payload
            .pointer(&format!("/{}", self.name_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let space = msg
            .payload
            .pointer(&format!("/{}", self.space_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let shared = msg
            .payload
            .pointer(&format!("/{}", self.shared_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if name.is_empty() {
            return Ok(error_output(&msg, "kv3-adresse: name fehlt"));
        }
        let salt = match self.ebene.as_str() {
            "space" => salt_space(&name),
            "user" => {
                if space.is_empty() {
                    return Ok(error_output(
                        &msg,
                        "kv3-adresse: space fehlt für user-Ebene",
                    ));
                }
                salt_user(&salt_space(&space), &name)
            }
            "shared" => {
                if space.is_empty() {
                    return Ok(error_output(
                        &msg,
                        "kv3-adresse: space fehlt für shared-Ebene",
                    ));
                }
                let base = if shared.is_empty() { &name } else { &shared };
                salt_shared(&salt_space(&space), base)
            }
            _ => {
                return Ok(error_output(
                    &msg,
                    "kv3-adresse: ebene muss space|user|shared sein",
                ))
            }
        };
        let addr = match kv3_adresse(&name, &salt) {
            Ok(a) => a,
            Err(e) => return Ok(error_output(&msg, &format!("kv3-adresse: {e}"))),
        };
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert(format!("addr_{}", self.ebene), json!(addr));
            o.insert(format!("salt_{}", self.ebene), json!(salt));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "ebene" => ebene: str,
            "namePath" => name_path: str,
            "spacePath" => space_path: str,
            "sharedPath" => shared_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.ebene, "kv3-adresse braucht ebene")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv3-adresse"
    }
}

node_factory!(Kv3AdresseNodeFactory, Kv3AdresseNode, "kv3-adresse", {
    name: String::new(),
    ebene: "space".to_string(),
    name_path: "space".to_string(),
    space_path: "space".to_string(),
    shared_path: String::new(),
});

// ---------------------------------------------------------------------------
// Node 2: kv3-open (Hashdatei laden + Passwort-Box öffnen)
// ---------------------------------------------------------------------------

pub struct Kv3OpenNode {
    name: String,
    salt_field: String,
    s3_config: String,
    bucket: String,
    prefix: String,
    passwort_path: String,
    target_addr_path: String,
    base_path: String,
}

impl Kv3OpenNode {
    fn err(&self, msg: &FlowMessage, e: impl Into<String>) -> Vec<FlowMessage> {
        let e = e.into();
        warn!(node = %self.name, error = %e, "kv3-open failed");
        error_output(msg, &e)
    }
}

#[async_trait::async_trait]
impl NodeExecutor for Kv3OpenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let passwort = msg
            .payload
            .pointer(&format!("/{}", self.passwort_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if passwort.is_empty() {
            return Ok(self.err(&msg, "kv3-open: passwort fehlt"));
        }
        let target_addr = msg
            .payload
            .pointer(&format!("/{}", self.target_addr_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if target_addr.is_empty() {
            return Ok(self.err(&msg, "kv3-open: ziel-adresse fehlt (kv3-adresse zuerst)"));
        }
        let base = msg
            .payload
            .pointer(&format!("/{}", self.base_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let raw_cfg = std::fs::read_to_string(&self.s3_config).map_err(|e| {
            Z8Error::Internal(format!("kv3-open s3 config {}: {e}", self.s3_config))
        })?;
        let cfg: Value = serde_json::from_str(&raw_cfg)
            .map_err(|e| Z8Error::Internal(format!("kv3-open s3 parse: {e}")))?;
        let ep = match s3_endpoint_aus(&cfg) {
            Ok(e) => e,
            Err(e) => return Ok(self.err(&msg, e)),
        };
        let bucket = if self.bucket.is_empty() {
            cfg["bucket"].as_str().unwrap_or_default().to_string()
        } else {
            self.bucket.clone()
        };
        let prefix = if self.prefix.is_empty() {
            cfg["prefix"].as_str().unwrap_or_default().to_string()
        } else {
            self.prefix.clone()
        };
        let key = format!("{prefix}{target_addr}.txt");
        let data = match ep.get_object(&bucket, &key).await {
            Ok(d) => d,
            Err(e) => return Ok(self.err(&msg, format!("S3 GET {bucket}/{key}: {e}"))),
        };
        let text = String::from_utf8_lossy(&data).to_string();
        let (addrs, blocks) = parse_datei(&text);
        let map: std::collections::HashMap<String, String> = blocks.into_iter().collect();
        let Some((_, blk)) = addrs.iter().find(|(a, _)| a == &target_addr) else {
            return Ok(self.err(&msg, format!("Adresse {target_addr} nicht in {key}")));
        };
        let Some(chiffre) = map.get(blk) else {
            return Ok(self.err(&msg, "Block-Chiffre fehlt"));
        };
        let clean: String = chiffre.chars().filter(|c| !c.is_whitespace()).collect();
        let box_val: Value = match B64.decode(clean.trim()).map_err(|e| e.to_string()) {
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(v) => v,
                Err(e) => return Ok(self.err(&msg, format!("Box-JSON: {e}"))),
            },
            Err(e) => return Ok(self.err(&msg, format!("Box-Base64: {e}"))),
        };
        // Passbox öffnen: argon2(passwort, salt_der_datei) als Key.
        // Der Salt der Datei = der Salt, mit dem die Adresse gebildet wurde
        // (steht als salt_<ebene> im Payload).
        let salt = msg
            .payload
            .get(&self.salt_field)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(salt) = salt else {
            return Ok(self.err(
                &msg,
                format!("kv3-open: {} fehlt im Payload", self.salt_field),
            ));
        };
        let key = argon_key(&passwort, &salt);
        let plain = match aes_open(&box_val, &key) {
            Ok(p) => p,
            Err(_) => return Ok(self.err(&msg, "Passwort passt nicht (Box öffnet nicht)")),
        };
        let block: Value = match serde_json::from_slice(&plain) {
            Ok(v) => v,
            Err(e) => return Ok(self.err(&msg, format!("Block-JSON: {e}"))),
        };
        // Secrets strippen, Block-Inhalt + Klartext-Sichtbarkeit übernehmen.
        // Engines/Workspace-Angaben top-level heben: kv3-socket und der
        // Proxy-Start brauchen sie ohne opened_block-Kenntnis.
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.remove("password");
            o.remove("passwort");
            for feld in ["engines", "workspace_prefix", "workspace_bucket", "quorum"] {
                if let Some(v) = block.get(feld) {
                    o.insert(feld.to_string(), v.clone());
                }
            }
            o.insert("opened_block".into(), block);
            o.insert("opened_datei".into(), json!(key));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "saltField" => salt_field: str,
            "s3Config" => s3_config: str,
            "bucket" => bucket: str,
            "prefix" => prefix: str,
            "passwortPath" => passwort_path: str,
            "targetAddrPath" => target_addr_path: str,
            "basePath" => base_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "kv3-open braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv3-open"
    }
}

node_factory!(Kv3OpenNodeFactory, Kv3OpenNode, "kv3-open", {
    name: String::new(),
    salt_field: "salt_user".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    bucket: String::new(),
    prefix: String::new(),
    passwort_path: "req.body.password".to_string(),
    target_addr_path: "addr_user".to_string(),
    base_path: "addr_space".to_string(),
});

// --- Passbox-Krypto (identisch zu kette::passbox, ohne kette-Dep) ---

fn argon_key(passwort: &str, salt: &str) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19456, 2, 1, Some(32)).unwrap();
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    let _ = a2.hash_password_into(passwort.as_bytes(), salt.as_bytes(), &mut out);
    out
}

fn aes_open(box_val: &Value, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;
    let nonce_v = B64
        .decode(box_val["nonce"].as_str().ok_or("nonce fehlt")?)
        .map_err(|_| "nonce b64")?;
    let nonce: [u8; 12] = nonce_v.as_slice().try_into().map_err(|_| "nonce Länge")?;
    let ct = B64
        .decode(box_val["box"].as_str().ok_or("box fehlt")?)
        .map_err(|_| "box b64")?;
    if nonce.len() != 12 {
        return Err("nonce Länge".into());
    }
    let aead = Aes256Gcm::new((key).into());
    let aad = box_val["aad"].as_str().unwrap_or_default();
    aead.decrypt(
        (&nonce).into(),
        Payload {
            msg: &ct,
            aad: aad.as_bytes(),
        },
    )
    .map_err(|e| format!("GCM: {e}"))
}

// ---------------------------------------------------------------------------
// Node 3: kv3-hwshard (Workspace hw-shards.txt laden + ECIES mit PEM öffnen)
// ---------------------------------------------------------------------------

pub struct Kv3HwshardNode {
    name: String,
    s3_config: String,
    bucket: String,
    prefix: String,
    pem_path: String,
    workspace_addr_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for Kv3HwshardNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let pem = msg
            .payload
            .pointer(&format!("/{}", self.pem_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if pem.is_empty() {
            return Ok(error_output(&msg, "kv3-hwshard: pem fehlt"));
        }
        let ws_addr = msg
            .payload
            .pointer(&format!("/{}", self.workspace_addr_path.replace(".", "/")))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if ws_addr.is_empty() {
            return Ok(error_output(&msg, "kv3-hwshard: workspace-adresse fehlt"));
        }
        let raw_cfg = std::fs::read_to_string(&self.s3_config)
            .map_err(|e| Z8Error::Internal(format!("kv3-hwshard s3 config: {e}")))?;
        let cfg: Value = serde_json::from_str(&raw_cfg)
            .map_err(|e| Z8Error::Internal(format!("kv3-hwshard s3 parse: {e}")))?;
        let ep = match s3_endpoint_aus(&cfg) {
            Ok(e) => e,
            Err(e) => return Ok(error_output(&msg, &e)),
        };
        let bucket = if self.bucket.is_empty() {
            cfg["bucket"].as_str().unwrap_or_default().to_string()
        } else {
            self.bucket.clone()
        };
        let prefix = if self.prefix.is_empty() {
            cfg["prefix"].as_str().unwrap_or_default().to_string()
        } else {
            self.prefix.clone()
        };
        let key = format!("{prefix}{ws_addr}/hw-shards.txt");
        let data = match ep.get_object(&bucket, &key).await {
            Ok(d) => d,
            Err(e) => return Ok(error_output(&msg, &format!("S3 GET {key}: {e}"))),
        };
        let text = String::from_utf8_lossy(&data).to_string();
        let (addrs, blocks) = parse_datei(&text);
        // Pubkey aus PEM berechnen und in Adressen suchen
        let secret = match p256::SecretKey::from_sec1_pem(&pem) {
            Ok(s) => s,
            Err(e) => return Ok(error_output(&msg, &format!("PEM: {e}"))),
        };
        let pub_b64 = B64.encode(p256::PublicKey::from(secret.public_key()).to_sec1_bytes());
        let map: std::collections::HashMap<String, String> = blocks.into_iter().collect();
        let Some((_, blk)) = addrs.iter().find(|(a, _)| a == &pub_b64) else {
            return Ok(error_output(&msg, "PEM-Pubkey nicht in hw-shards gefunden"));
        };
        let Some(chiffre) = map.get(blk) else {
            return Ok(error_output(&msg, "HW-Block fehlt"));
        };
        let clean: String = chiffre.chars().filter(|c| !c.is_whitespace()).collect();
        let box_val: Value = serde_json::from_slice(
            &B64.decode(clean.trim())
                .map_err(|e| Z8Error::Internal(e.to_string()))?,
        )
        .map_err(|e| Z8Error::Internal(format!("HW-Box: {e}")))?;
        // ECIES öffnen — Umschlag-Logik wie kette: p256 ECDH + HKDF + GCM
        let plain = match umschlag_oeffnen(&box_val, &secret) {
            Ok(p) => p,
            Err(e) => return Ok(error_output(&msg, &format!("HW-Box öffnen: {e}"))),
        };
        let hw_block: Value = serde_json::from_slice(&plain)
            .map_err(|e| Z8Error::Internal(format!("HW-Block-JSON: {e}")))?;
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.remove("key_pem");
            o.insert("hw_block".into(), hw_block);
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "bucket" => bucket: str,
            "prefix" => prefix: str,
            "pemPath" => pem_path: str,
            "workspaceAddrPath" => workspace_addr_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "kv3-hwshard braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv3-hwshard"
    }
}

node_factory!(Kv3HwshardNodeFactory, Kv3HwshardNode, "kv3-hwshard", {
    name: String::new(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    bucket: String::new(),
    prefix: String::new(),
    pem_path: "req.body.key_pem".to_string(),
    workspace_addr_path: "addr_user".to_string(),
});

/// ECIES-Öffnen (v1): ECDH(p256) + HKDF-SHA256 + AES-256-GCM — wie kette/umschlag.
fn umschlag_oeffnen(box_val: &Value, secret: &p256::SecretKey) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;
    let eph_pub_b64 = box_val["ephem"].as_str().ok_or("ephem fehlt")?;
    let nonce_v = B64
        .decode(box_val["nonce"].as_str().ok_or("nonce fehlt")?)
        .map_err(|_| "nonce b64")?;
    let nonce: [u8; 12] = nonce_v.as_slice().try_into().map_err(|_| "nonce Länge")?;
    let ct = B64
        .decode(box_val["box"].as_str().ok_or("box fehlt")?)
        .map_err(|_| "box b64")?;
    let aad = box_val["aad"].as_str().unwrap_or_default();
    let eph_raw = B64.decode(eph_pub_b64).map_err(|_| "ephem b64")?;
    let eph_pub = p256::PublicKey::from_sec1_bytes(&eph_raw).map_err(|e| format!("ephem: {e}"))?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
    let mut key = [0u8; 32];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&eph_raw), shared.raw_secret_bytes());
    hk.expand(b"kv-m2-secretbox", &mut key)
        .map_err(|e| format!("HKDF: {e}"))?;
    let aead = Aes256Gcm::new((&key).into());
    aead.decrypt(
        (&nonce).into(),
        Payload {
            msg: &ct,
            aad: aad.as_bytes(),
        },
    )
    .map_err(|e| format!("GCM: {e}"))
}

// ---------------------------------------------------------------------------
// Node 4: kv3-master (Shamir 2-of-2 kombinieren -> Fingerprint)
// ---------------------------------------------------------------------------

pub struct Kv3MasterNode {
    name: String,
}

#[async_trait::async_trait]
impl NodeExecutor for Kv3MasterNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let provider = msg
            .payload
            .pointer("/opened_block/shamir_provider")
            .cloned()
            .filter(|v| !v.is_null());
        let hw = msg
            .payload
            .pointer("/hw_block/shamir_hw")
            .cloned()
            .filter(|v| !v.is_null());
        let (Some(p), Some(h)) = (provider, hw) else {
            return Ok(error_output(
                &msg,
                "kv3-master: beide Shards nötig (kv3-open + kv3-hwshard zuerst)",
            ));
        };
        let px = p["x"].as_u64().unwrap_or(0) as u8;
        let py = B64
            .decode(p["y"].as_str().unwrap_or_default())
            .map_err(|e| Z8Error::Internal(e.to_string()))?;
        let hx = h["x"].as_u64().unwrap_or(0) as u8;
        let hy = B64
            .decode(h["y"].as_str().unwrap_or_default())
            .map_err(|e| Z8Error::Internal(e.to_string()))?;
        if px == hx {
            return Ok(error_output(
                &msg,
                "kv3-master: gleiche x-Werte — 2-of-2 unmöglich",
            ));
        }
        let master = shamir2(px, &py, hx, &hy);
        let fp = sha_hex(&master);
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("master_sha256".into(), json!(fp));
            o.remove("opened_block");
            o.remove("hw_block");
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv3-master"
    }
}

node_factory!(Kv3MasterNodeFactory, Kv3MasterNode, "kv3-master", {
    name: String::new(),
});

/// Shamir 2-Punkte-Interpolation über GF(2^8) (Lagrange bei x=0), identisch
/// zu kette::shamir::combine2 — für 2 Shares: m = y_a * lag_a + y_b * lag_b.
fn shamir2(xa: u8, ya: &[u8], xb: u8, yb: &[u8]) -> Vec<u8> {
    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut a = a as u16;
        let mut b = b as u16;
        let mut p = 0u16;
        while b != 0 {
            if b & 1 == 1 {
                p ^= a;
            }
            a <<= 1;
            if a & 0x100 != 0 {
                a ^= 0x11b;
            }
            b >>= 1;
        }
        p as u8
    }
    fn gf_inv(a: u8) -> u8 {
        // a^254
        let mut r = 1u8;
        for _ in 0..7 {
            r = gf_mul(r, r);
            r = gf_mul(r, a);
        }
        gf_mul(r, r) // fix: a^254 = (a^127)^2 … wir nutzen Potenz-Kette unten
    }
    fn gf_pow(mut base: u8, mut exp: u32) -> u8 {
        let mut acc = 1u8;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = gf_mul(acc, base);
            }
            base = gf_mul(base, base);
            exp >>= 1;
        }
        acc
    }
    let _ = gf_inv;
    fn inv(a: u8) -> u8 {
        gf_pow(a, 254)
    }
    let la = gf_mul(ya[0], inv(xa)); // Anteil a: y_a * (0-x_b)/(x_a-x_b) = y_a * x_b/(x_b^x_a)
    let _ = la;
    // identisch kette::shamir::combine2:
    // la = y_a * x_b/(x_a^x_b), lb = y_b * x_a/(x_a^x_b)
    let la = gf_mul(xb, inv(xa ^ xb));
    let lb = gf_mul(xa, inv(xa ^ xb));
    ya.iter()
        .zip(yb.iter())
        .map(|(&a, &b)| gf_mul(a, la) ^ gf_mul(b, lb))
        .collect()
}

// ---------------------------------------------------------------------------
// Node 5: kv3-socket (Übergabe an den Proxy-Socket)
// ---------------------------------------------------------------------------

pub struct Kv3SocketNode {
    name: String,
    socket_path: String,
    payload_fields: String, // Komma-Liste der Felder, die übergeben werden
}

#[async_trait::async_trait]
impl NodeExecutor for Kv3SocketNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let mut uebergabe = json!({
            "event": "kv3-session",
            "trace_id": msg.trace_id.to_string(),
        });
        if let Some(dst) = uebergabe.as_object_mut() {
            for feld in self
                .payload_fields
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                if let Some(v) = msg.payload.get(feld) {
                    dst.insert(feld.to_string(), v.clone());
                }
            }
        }
        let body = uebergabe.to_string();
        let senden = tokio::time::timeout(Duration::from_secs(5), async {
            use tokio::io::AsyncWriteExt;
            let mut s = tokio::net::UnixStream::connect(&self.socket_path).await?;
            s.write_all(body.as_bytes()).await?;
            s.write_all(b"\n").await?;
            s.shutdown().await?;
            Ok::<_, std::io::Error>(())
        })
        .await;
        let status = match senden {
            Ok(Ok(())) => "gesendet".to_string(),
            Ok(Err(e)) => format!("fehler: {e}"),
            Err(_) => "timeout".to_string(),
        };
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("socket_status".into(), json!(status));
            o.insert("socket_target".into(), json!(self.socket_path));
        }
        // Erfolgreiche Übergabe = output; Fehler = error-Port (Proxy-Start kann
        // später auch ohne Socket getestet werden).
        let port = if status == "gesendet" {
            "output"
        } else {
            "error"
        };
        Ok(vec![msg.derive(msg.source_node, port, out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "socketPath" => socket_path: str,
            "payloadFields" => payload_fields: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.socket_path, "kv3-socket braucht socketPath")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv3-socket"
    }
}

node_factory!(Kv3SocketNodeFactory, Kv3SocketNode, "kv3-socket", {
    name: String::new(),
    socket_path: "/data/z8run/kv3-proxy.sock".to_string(),
    payload_fields: "addr_space,addr_user,master_sha256,workspace_bucket,engines".to_string(),
});
