//! Setup-Node: webauthn-challenge (serverseitig gespeichert, einmalig).

use serde_json::{json, Value};

use super::setup_challenge;
use super::setup_io::{body, text};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub struct WebauthnChallengeNode {
    name: String,
    rp_id: String,
    origin: String,
    challenge_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for WebauthnChallengeNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let challenge = super::setup_webauthn::b64url(
            &(0u8..32).map(|_| rand::random::<u8>()).collect::<Vec<u8>>(),
        );
        let Some(user) = text(req, "user") else {
            let err = json!({"status": 400, "error": "webauthn-challenge: user fehlt"});
            return Ok(vec![msg.derive(msg.source_node, "error", err)]);
        };
        if let Err(e) = setup_challenge::speichere(&self.challenge_dir, user, &challenge, 300) {
            let err = json!({"status": 500, "error": format!("webauthn-challenge: {e}")});
            return Ok(vec![msg.derive(msg.source_node, "error", err)]);
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("webauthn_challenge".into(), json!(challenge));
            o.insert("rp_id".into(), json!(text(req, "rpId").unwrap_or(&self.rp_id)));
            o.insert("origin".into(), json!(text(req, "origin").unwrap_or(&self.origin)));
            if let Some(u) = req.get("user") {
                o.insert("user".into(), u.clone());
            }
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "rpId" => rp_id: str,
            "origin" => origin: str,
            "challengeDir" => challenge_dir: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "webauthn-challenge"
    }
}

node_factory!(WebauthnChallengeNodeFactory, WebauthnChallengeNode, "webauthn-challenge", {
    name: "webauthn-challenge".to_string(),
    rp_id: "localhost".to_string(),
    origin: "http://localhost:7700".to_string(),
    challenge_dir: "/data/z8run/setup-challenges".to_string(),
});

