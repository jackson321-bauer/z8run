//! setup-auth: Prüft Setup-Key-Quorum + ECDSA-Signatur. Ohne = 403.
//!
//! Der Betreiber sendet `setup_pems` (mind. 2) und eine Signatur über den
//! String `signed`. Der String MUSS mit `<op>:<space>:` beginnen, damit eine
//! Signatur nicht für eine andere Operation wiederverwendet werden kann.

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, text};
use super::setup_registry as reg;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub struct SetupAuthNode {
    name: String,
    s3_config: String,
    registry_key: String,
    shards_key: String,
    pem_path: String,
    signature_path: String,
    signed_path: String,
    op: String,
}

fn verweigert(msg: &FlowMessage, grund: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": 403, "error": grund.into(), "auth": "setup-key" }),
    )]
}

#[async_trait::async_trait]
impl NodeExecutor for SetupAuthNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let pems = reg::pems_aus(req, &self.pem_path);
        if pems.len() < 2 {
            return Ok(verweigert(
                &msg,
                "Setup-Auth: mindestens 2 Setup-PEMs nötig (2-of-N)",
            ));
        }
        let cfg = match reg::cfg_aus(&self.s3_config, req) {
            Ok(c) => c,
            Err(e) => return Ok(verweigert(&msg, format!("setup-auth: {e}"))),
        };
        let master = match reg::master_aus_pems(&cfg, &self.shards_key, &pems).await {
            Ok(m) => m,
            Err(e) => return Ok(verweigert(&msg, format!("setup-auth: {e}"))),
        };
        let master_hex = hex::encode(&master);
        let registry = match reg::lade_registry(&cfg, &self.registry_key, &master_hex).await {
            Ok(r) => r,
            Err(e) => return Ok(verweigert(&msg, format!("setup-auth registry: {e}"))),
        };
        let registered: Vec<String> = registry["setup_keys"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| k["pub_b64"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for pem in &pems {
            match sc::pem_pub_b64(pem) {
                Ok(pub_b64) if registered.contains(&pub_b64) => {}
                _ => return Ok(verweigert(&msg, "Setup-Auth: unbekannter Setup-Key")),
            }
        }
        let signed = text(req, &self.signed_path).unwrap_or_default();
        let signature = text(req, &self.signature_path).unwrap_or_default();
        if signed.is_empty() || signature.is_empty() {
            return Ok(verweigert(&msg, "Setup-Auth: signed/signature fehlt"));
        }
        let space = registry["space"].as_str().unwrap_or_default().to_string();
        let prefix = format!("{}:{}:", self.op, space);
        if !signed.starts_with(&prefix) {
            return Ok(verweigert(
                &msg,
                format!("Setup-Auth: signed muss mit {prefix} beginnen"),
            ));
        }
        let signer_pub = match sc::pem_pub_b64(&pems[0]) {
            Ok(p) => p,
            Err(e) => return Ok(verweigert(&msg, format!("Setup-Auth: {e}"))),
        };
        if !sc::pruefe_signatur(&signer_pub, signed.as_bytes(), signature) {
            return Ok(verweigert(&msg, "Setup-Auth: Signatur ungültig"));
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("setup_master_hex".into(), json!(master_hex));
            o.insert("setup_registry".into(), registry);
            o.insert(
                "setup_auth".into(),
                json!({
                    "ok": true,
                    "op": self.op,
                    "space": space,
                    "keys_used": pems.len(),
                    "signer_pub": signer_pub,
                }),
            );
            o.remove("setup_pems");
            o.remove("setup_signature");
            o.remove("setup_signed");
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "registryKey" => registry_key: str,
            "shardsKey" => shards_key: str,
            "pemsPath" => pem_path: str,
            "signaturePath" => signature_path: str,
            "signedPath" => signed_path: str,
            "op" => op: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-auth"
    }
}

node_factory!(SetupAuthNodeFactory, SetupAuthNode, "setup-auth", {
    name: "setup-auth".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
    shards_key: reg::SHARDS_KEY.to_string(),
    pem_path: "setup_pems".to_string(),
    signature_path: "setup_signature".to_string(),
    signed_path: "setup_signed".to_string(),
    op: "op".to_string(),
});
