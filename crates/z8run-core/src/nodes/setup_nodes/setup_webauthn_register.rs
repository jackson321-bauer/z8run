//! Setup-Node: webauthn-register (Attestation fmt=none, ES256).

use serde_json::{json, Value};

use super::setup_challenge;
use super::setup_io::{body, text};
use super::setup_registry as reg;
use super::setup_webauthn::verarbeite_registrierung;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

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
        let cred = match verarbeite_registrierung(
            cd_b64, att_b64, challenge, &origin, &rp_id, &user,
        ) {
            Ok(c) => c,
            Err(e) => return Ok(err(format!("webauthn-register: {e}"))),
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
