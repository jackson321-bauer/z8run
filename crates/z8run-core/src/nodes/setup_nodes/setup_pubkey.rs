//! /user-pubkey-add: neuen HW-Pubkey registrieren + HW-Share an ihn
//! versiegeln (Resharding-Vorbereitung). Nur mit Setup-Key.

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::body;
use super::setup_plugin::finde_user;
use super::setup_registry as reg;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub const ESCROW_SALT: &str = "kv3-setup-escrow";

pub struct PubkeyAddNode {
    name: String,
    s3_config: String,
    registry_key: String,
}

fn fehler(msg: &FlowMessage, status: u16, text: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": status, "error": text.into() }),
    )]
}

#[async_trait::async_trait]
impl NodeExecutor for PubkeyAddNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 403, "user-pubkey-add: setup-auth fehlt"));
        };
        let mut registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
        let cfg = match reg::cfg_aus_registry(&self.s3_config, req, &registry) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add: {e}"))),
        };
        let Some(user) = finde_user(&registry, req) else {
            return Ok(fehler(&msg, 400, "user-pubkey-add: User nicht in Registry"));
        };
        let addr = user["addr_user"].as_str().unwrap_or_default().to_string();
        let pub_b64 = match req.get("pub_b64").and_then(|v| v.as_str()) {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => match req.get("pem").and_then(|v| v.as_str()) {
                Some(pem) => match sc::pem_pub_b64(pem) {
                    Ok(p) => p,
                    Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add: {e}"))),
                },
                None => return Ok(fehler(&msg, 400, "user-pubkey-add: pub_b64/pem fehlt")),
            },
        };
        let escrow_key = format!("setup/escrow/{addr}.txt");
        let escrow_text = match cfg.get(&escrow_key).await {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add escrow: {e}"))),
        };
        let (ea, eb) = sc::hashdatei_parsen(&escrow_text);
        let Some((_, eblock)) = ea.iter().find(|(a, _)| a == &addr) else {
            return Ok(fehler(&msg, 400, "user-pubkey-add: Escrow-Eintrag fehlt"));
        };
        let Some(echiffre) = eb.iter().find(|(b, _)| b == eblock).map(|(_, c)| c.clone()) else {
            return Ok(fehler(&msg, 400, "user-pubkey-add: Escrow-Block fehlt"));
        };
        let ebox = match sc::box_aus_b64(&echiffre) {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add: {e}"))),
        };
        let escrow = match sc::passbox_oeffne(&ebox, master_hex, ESCROW_SALT) {
            Ok(v) => v,
            Err(e) => return Ok(fehler(&msg, 403, format!("user-pubkey-add escrow: {e}"))),
        };
        let hw_text_key = format!("workspaces/{addr}/hw-shards.txt");
        let hw_text = match cfg.get(&hw_text_key).await {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add hw-shards: {e}"))),
        };
        let (ha, hb) = sc::hashdatei_parsen(&hw_text);
        if ha.iter().any(|(a, _)| a == &pub_b64) {
            return Ok(fehler(&msg, 409, "user-pubkey-add: Pubkey bereits registriert"));
        }
        let block = json!({
            "shamir_hw": escrow["shamir_hw"],
            "hash_datei": format!("b2b/{addr}.txt"),
            "added_by": "setup-key",
        });
        let hbox = match sc::hwbox(&pub_b64, &block, "kv3-hw") {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add: {e}"))),
        };
        let box_b64 = match sc::box_b64(&hbox) {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 400, format!("user-pubkey-add: {e}"))),
        };
        let mut addrs = ha.clone();
        let mut chiffren: Vec<(String, String)> = hb.clone();
        let new_block = format!("Block-{}", ha.len() + 1);
        addrs.push((pub_b64.clone(), new_block.clone()));
        chiffren.push((new_block.clone(), box_b64));
        let neu = sc::hashdatei_bauen(&addrs, &chiffren);
        let sha = sc::sha_hex(neu.as_bytes());
        if let Err(e) = cfg.put(&hw_text_key, neu.into_bytes()).await {
            return Ok(fehler(&msg, 400, format!("user-pubkey-add put: {e}")));
        }
        if let Some(users) = registry["users"].as_array_mut() {
            for u in users.iter_mut() {
                if u["addr_user"] == json!(addr) {
                    if !u["pubkeys"].is_array() {
                        u["pubkeys"] = json!([]);
                    }
                    u["pubkeys"].as_array_mut().unwrap().push(json!({
                        "name": req.get("name").and_then(|v| v.as_str()).unwrap_or("added"),
                        "pub_b64": pub_b64,
                        "added_at": chrono::Utc::now().to_rfc3339(),
                    }));
                }
            }
        }
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        if let Err(e) = reg::speichere_registry(&cfg, &self.registry_key, master_hex, &registry).await {
            return Ok(fehler(&msg, 400, format!("user-pubkey-add registry: {e}")));
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("setup_registry".into(), registry);
            o.insert("pubkey_added".into(), json!({
                "ok": true, "user_addr": addr, "pub_b64": pub_b64,
                "block": new_block, "hw_shards_sha256": sha,
            }));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "registryKey" => registry_key: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "user-pubkey-add"
    }
}

node_factory!(PubkeyAddNodeFactory, PubkeyAddNode, "user-pubkey-add", {
    name: "user-pubkey-add".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
});
