//! Setup-Node: validate (space, users, engines, quorum; keine Shared-Parameter).

use serde_json::{json, Value};

use super::setup_io::{body, text};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

fn fehler(msg: &FlowMessage, status: u16, text: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": status, "error": text.into() }),
    )]
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

pub struct SetupValidateNode {
    name: String,
    engines: String,
    default_quorum: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SetupValidateNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let space = text(req, "space").unwrap_or_default().trim();
        if space.is_empty() {
            return Ok(fehler(&msg, 400, "space fehlt"));
        }
        if space.len() > 64 || !space.chars().all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c)) {
            return Ok(fehler(&msg, 400, "space: nur [A-Za-z0-9 _.-], max 64"));
        }
        for verboten in ["shared", "shared_dbs", "shared_databases", "transfer_buckets"] {
            if req.get(verboten).map(|v| !v.is_null()).unwrap_or(false) {
                return Ok(fehler(
                    &msg,
                    400,
                    format!("{verboten} ist im lokalen Setup verboten (D6)"),
                ));
            }
        }
        let Some(users) = req.get("users").and_then(|v| v.as_array()) else {
            return Ok(fehler(&msg, 400, "users[] fehlt"));
        };
        if users.is_empty() {
            return Ok(fehler(&msg, 400, "mindestens ein Userspace nötig"));
        }
        let erlaubt: Vec<&str> = self.engines.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let mut gesehen = std::collections::HashSet::new();
        for (i, u) in users.iter().enumerate() {
            let name = u["name"].as_str().unwrap_or_default().trim();
            if name.is_empty() {
                return Ok(fehler(&msg, 400, format!("users[{i}].name fehlt")));
            }
            if !gesehen.insert(name.to_string()) {
                return Ok(fehler(&msg, 400, format!("User {name} doppelt")));
            }
            if u["password"].as_str().unwrap_or_default().len() < 8 {
                return Ok(fehler(&msg, 400, format!("users[{i}].password min. 8 Zeichen")));
            }
            if !erlaubt.is_empty() {
                if let Some(engines) = u.get("engines").and_then(|v| v.as_array()) {
                    for e in engines {
                        let e = e.as_str().unwrap_or_default();
                        if !erlaubt.contains(&e) {
                            return Ok(fehler(&msg, 400, format!("Engine {e} nicht erlaubt")));
                        }
                    }
                }
            }
        }
        let quorum = req.get("quorum").cloned().unwrap_or_else(|| {
            serde_json::from_str(&self.default_quorum).unwrap_or_else(|_| json!({"n": 3, "threshold": 2}))
        });
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("valid".into(), json!(true));
            o.insert("space".into(), json!(space));
            o.insert("quorum".into(), quorum);
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "engines" => engines: str,
            "defaultQuorum" => default_quorum: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-validate"
    }
}

node_factory!(SetupValidateNodeFactory, SetupValidateNode, "setup-validate", {
    name: "setup-validate".to_string(),
    engines: "demo,fts5,vec0".to_string(),
    default_quorum: "{\"n\":3,\"threshold\":2}".to_string(),
});

