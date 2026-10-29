//! Setup-Node: webauthn-register (Attestation fmt=none, ES256).

use serde_json::{json, Value};

use super::setup_challenge;
use super::setup_crypto as sc;
use super::setup_io::{body, text};
use super::setup_pqc as pqc;
use super::setup_registry as reg;
use super::setup_webauthn::verarbeite_registrierung;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

/// Publickey-Registry je User (nur Pubkeys, kein Secret) — vom Login-Node
/// gelesen, damit der Login KEINEN Setup-Master braucht.
async fn schreibe_public_registry(
    cfg: &super::setup_io::S3Cfg,
    addr: &str,
    user: &str,
    cred: &Value,
) -> Result<(), String> {
    let key = format!("b2b/{addr}-webauthn.json");
    let mut reg = match cfg.get(&key).await {
        Ok(d) => serde_json::from_slice(&d).unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    };
    if !reg.is_object() {
        reg = json!({});
    }
    if reg["credentials"].as_array().is_none() {
        reg["credentials"] = json!([]);
    }
    reg["format"] = json!("z8-webauthn-registry/1");
    reg["user"] = json!(user);
    reg["addr_user"] = json!(addr);
    if let Some(arr) = reg["credentials"].as_array_mut() {
        arr.retain(|c| c["credential_id"] != cred["credential_id"]);
        arr.push(cred.clone());
    }
    reg["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
    let data = serde_json::to_vec_pretty(&reg).map_err(|e| e.to_string())?;
    cfg.put(&key, data).await?;
    Ok(())
}

/// Siegelt den HW-Shard ZUSÄTZLICH hybrid v3 an den WebAuthn-Credential-
/// Pubkey (ECDH) ∥ ML-KEM-1024-Pubkey des Credentials (Stahlgitter-Pflicht).
async fn haenge_credential_box(
    cfg: &super::setup_io::S3Cfg,
    master_hex: &str,
    addr: &str,
    cred: &Value,
    pqc_pub: &str,
) -> Result<(), String> {
    let raw = cfg.get(&format!("setup/escrow/{addr}.txt")).await?;
    let (_, blocks) = sc::hashdatei_parsen(&String::from_utf8_lossy(&raw));
    let chiffre = blocks.first().ok_or("Escrow-Block fehlt")?.1.clone();
    let escrow = sc::passbox_oeffne(
        &sc::box_aus_b64(&chiffre)?,
        master_hex,
        "kv3-setup-escrow",
    )?;
    let hw_block = json!({
        "shamir_hw": escrow["shamir_hw"].clone(),
        "hash_datei": escrow["hash_datei"].clone(),
    });
    let pub_b64 = cred["pub_b64"].as_str().unwrap_or_default().to_string();
    let hb = pqc::hwbox_v3(&pub_b64, pqc_pub, &hw_block, "kv3-hw")?;
    let hw_key = format!("workspaces/{addr}/hw-shards.txt");
    let (mut addrs, mut chiffren) =
        sc::hashdatei_parsen(&String::from_utf8_lossy(&cfg.get(&hw_key).await?));
    addrs.retain(|(a, _)| a != &pub_b64);
    let keep: std::collections::HashSet<String> = addrs.iter().map(|(_, b)| b.clone()).collect();
    chiffren.retain(|(b, _)| keep.contains(b));
    let block_name = format!("Block-webauthn-{}", &sc::sha_hex(pub_b64.as_bytes())[..8]);
    addrs.push((pub_b64, block_name.clone()));
    chiffren.push((block_name, sc::box_b64(&hb)?));
    cfg.put(&hw_key, sc::hashdatei_bauen(&addrs, &chiffren).into_bytes())
        .await?;
    Ok(())
}

pub struct WebauthnRegisterNode {
    name: String,
    s3_config: String,
    registry_key: String,
    master_path: String,
    challenge_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for WebauthnRegisterNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let err = |e: String| vec![msg.derive(msg.source_node, "error", json!({"status": 403, "error": e}))];
        let Some(master_hex) = text(req, &self.master_path) else {
            return Ok(err("webauthn-register: Setup-Auth fehlt".into()));
        };
        let cfg = match reg::cfg_aus(&self.s3_config, req) {
            Ok(c) => c,
            Err(e) => return Ok(err(format!("webauthn-register: {e}"))),
        };
        let mut registry = match reg::lade_registry(&cfg, &self.registry_key, master_hex).await {
            Ok(r) => r,
            Err(e) => return Ok(err(format!("webauthn-register registry: {e}"))),
        };
        let user = text(req, "user").unwrap_or_default().to_string();
        let rp_id = text(req, "rpId").unwrap_or("localhost").to_string();
        let origin = text(req, "origin").unwrap_or("http://localhost:7700").to_string();
        let Some(challenge) = text(req, "challenge") else {
            return Ok(err("webauthn-register: challenge fehlt".into()));
        };
        let att_b64 = text(req, "attestationObject").unwrap_or_default();
        let cd_b64 = text(req, "clientDataJSON").unwrap_or_default();
        if let Err(e) = setup_challenge::verbrauche(&self.challenge_dir, &user, challenge) {
            return Ok(err(format!("webauthn-register challenge: {e}")));
        }
        let mut cred = match verarbeite_registrierung(
            cd_b64, att_b64, challenge, &origin, &rp_id, &user,
        ) {
            Ok(c) => c,
            Err(e) => return Ok(err(format!("webauthn-register: {e}"))),
        };
        let pqc_pub = text(req, "pqc_pub_b64").unwrap_or_default().to_string();
        if let Some(o) = cred.as_object_mut() {
            o.insert("pqc_pub_b64".into(), json!(pqc_pub));
            o.insert(
                "key_type".into(),
                json!(if pqc_pub.is_empty() {
                    "webauthn-hardware"
                } else {
                    "webauthn-software"
                }),
            );
        }
        let space = registry["space"].as_str().unwrap_or_default().to_string();
        let addr = registry["users"]
            .as_array()
            .and_then(|a| a.iter().find(|u| u["name"] == json!(user)))
            .and_then(|u| u["addr_user"].as_str())
            .map(str::to_string)
            .or_else(|| {
                let salt = sc::salt_user(&sc::salt_space(&space), &user);
                sc::kette::adresse(&user, &salt).ok()
            });
        let Some(addr) = addr else {
            return Ok(err("webauthn-register: addr_user nicht ableitbar".into()));
        };
        if !registry["webauthn"].is_object() {
            registry["webauthn"] = json!({});
        }
        let list = registry["webauthn"]
            .as_object_mut()
            .unwrap()
            .entry(user.clone())
            .or_insert_with(|| json!([]));
        if let Some(arr) = list.as_array_mut() {
            arr.retain(|c| c["credential_id"] != cred["credential_id"]);
            arr.push(cred.clone());
        }
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        if let Err(e) = reg::speichere_registry(&cfg, &self.registry_key, master_hex, &registry).await {
            return Ok(err(format!("webauthn-register save: {e}")));
        }
        if let Err(e) = schreibe_public_registry(&cfg, &addr, &user, &cred).await {
            return Ok(err(format!("webauthn-register public registry: {e}")));
        }
        if !pqc_pub.is_empty() {
            if let Err(e) = haenge_credential_box(&cfg, master_hex, &addr, &cred, &pqc_pub).await {
                return Ok(err(format!("webauthn-register credential box: {e}")));
            }
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("webauthn_credential".into(), cred);
            o.insert("ok".into(), json!(true));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "registryKey" => registry_key: str,
            "masterPath" => master_path: str,
            "challengeDir" => challenge_dir: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "webauthn-register"
    }
}

node_factory!(WebauthnRegisterNodeFactory, WebauthnRegisterNode, "webauthn-register", {
    name: "webauthn-register".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
    master_path: "setup_master_hex".to_string(),
    challenge_dir: "/data/z8run/setup-challenges".to_string(),
});
