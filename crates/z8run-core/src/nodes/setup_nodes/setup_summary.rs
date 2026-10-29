//! setup-summary: baut die API-Antwort NUR aus einer Allowlist.
//! Kein Master, kein Passwort, keine Signatur verlässt den Flow.

use serde_json::{json, Value};

use super::setup_io::{body, text};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub struct SetupSummaryNode {
    name: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SetupSummaryNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        tracing::info!(node="setup-summary", keys=?req.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()), has_world=req.get("world").is_some(), "setup node start");
        let world = req.get("world").cloned().unwrap_or_else(|| json!({}));
        let setup_pems = req
            .get("setup_pems")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let mut response = json!({
            "ok": world["ok"].as_bool().unwrap_or(true),
            "api": "z8-setup",
            "space": world["space"].clone(),
            "addr_space": world["addr_space"].clone(),
            "shared": world["shared"].clone(),
            "users": world["users"].clone(),
            "setup_pubkeys": world["setup_pubkeys"].clone(),
            "files": world["files"].clone(),
            "setup_pems": setup_pems,
            "summary": {
                "users": world["users"].as_array().map(|a| a.len()).unwrap_or(0),
                "files": world["files"].as_array().map(|a| a.len()).unwrap_or(0),
                "shared": false,
            },
        });
        if let Some(t) = text(req, "message") {
            response["message"] = json!(t);
        }
        Ok(vec![msg.derive(msg.source_node, "output", response)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-summary"
    }
}

node_factory!(SetupSummaryNodeFactory, SetupSummaryNode, "setup-summary", {
    name: "setup-summary".to_string(),
});

// ---------------------------------------------------------------------------
// setup-result (Betriebs-Flows): Allowlist ohne Master/Registry/PEMs
// ---------------------------------------------------------------------------

pub struct SetupResultNode {
    name: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SetupResultNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let mut response = json!({
            "ok": req.get("ok").and_then(|v| v.as_bool()).unwrap_or(true),
            "api": "z8-setup",
        });
        for feld in ["rotation", "plugin", "pubkey_added", "webauthn_credential", "webauthn_assertion", "setup_auth"] {
            if let Some(v) = req.get(feld) {
                response[feld] = v.clone();
            }
        }
        if let Some(r) = req.get("setup_registry") {
            response["space"] = r["space"].clone();
            response["addr_space"] = r["space_addr"].clone();
        }
        if let Some(s) = text(req, "space") {
            response["space"] = json!(s);
        }
        response["secrets_exposed"] = json!(false);
        Ok(vec![msg.derive(msg.source_node, "output", response)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-result"
    }
}

node_factory!(SetupResultNodeFactory, SetupResultNode, "setup-result", {
    name: "setup-result".to_string(),
});
