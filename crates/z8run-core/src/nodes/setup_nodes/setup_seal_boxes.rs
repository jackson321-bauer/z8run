//! Setup-Nodes S1: passbox-seal + hwbox-seal (Boxen versiegeln).

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, pfad, text};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::{error_output, require_non_empty};

fn ausgabe(msg: &FlowMessage, mut out: Value, port: &str) -> Vec<FlowMessage> {
    if !out.is_object() {
        out = json!({ "value": out });
    }
    vec![msg.derive(msg.source_node, port, out)]
}

// ---------------------------------------------------------------------------
// passbox-seal
// ---------------------------------------------------------------------------

pub struct PassboxSealNode {
    name: String,
    password_path: String,
    salt: String,
    salt_path: String,
    addr_path: String,
    block_path: String,
    block_name: String,
    aad: String,
}

#[async_trait::async_trait]
impl NodeExecutor for PassboxSealNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(passwort) = text(req, &self.password_path) else {
            return Ok(error_output(&msg, "passbox-seal: password fehlt"));
        };
        let salt = if !self.salt.is_empty() {
            self.salt.clone()
        } else {
            match text(req, &self.salt_path) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => return Ok(error_output(&msg, "passbox-seal: salt/saltPath fehlt")),
            }
        };
        let block = if !self.block_path.is_empty() {
            match pfad(req, &self.block_path) {
                Some(v) => v.clone(),
                None => return Ok(error_output(&msg, "passbox-seal: blockPath nicht gefunden")),
            }
        } else {
            req.get("block").cloned().unwrap_or_else(|| json!({}))
        };
        let box_val = match sc::passbox(passwort, &salt, &block, &self.aad) {
            Ok(b) => b,
            Err(e) => return Ok(error_output(&msg, &format!("passbox-seal: {e}"))),
        };
        let box_b64 = match sc::box_b64(&box_val) {
            Ok(b) => b,
            Err(e) => return Ok(error_output(&msg, &format!("passbox-seal: {e}"))),
        };
        let addr = text(req, &self.addr_path).unwrap_or_default().to_string();
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.remove("password");
            o.remove("passwort");
            o.insert("box".into(), box_val);
            o.insert(
                "secretbox".into(),
                json!({ "addr": addr, "block": self.block_name, "box_b64": box_b64 }),
            );
        }
        Ok(ausgabe(&msg, out, "output"))
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "passwordPath" => password_path: str,
            "salt" => salt: str,
            "saltPath" => salt_path: str,
            "addrPath" => addr_path: str,
            "blockPath" => block_path: str,
            "blockName" => block_name: str,
            "aad" => aad: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.password_path, "passbox-seal braucht passwordPath")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "passbox-seal"
    }
}

node_factory!(PassboxSealNodeFactory, PassboxSealNode, "passbox-seal", {
    name: "passbox-seal".to_string(),
    password_path: "password".to_string(),
    salt: String::new(),
    salt_path: "salt_user".to_string(),
    addr_path: "addr_user".to_string(),
    block_path: "block".to_string(),
    block_name: "Block-1".to_string(),
    aad: "kv3-user".to_string(),
});

// ---------------------------------------------------------------------------
// hwbox-seal
// ---------------------------------------------------------------------------

pub struct HwboxSealNode {
    name: String,
    pems_path: String,
    block_path: String,
    aad: String,
}

#[async_trait::async_trait]
impl NodeExecutor for HwboxSealNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let pems = pfad(req, &self.pems_path)
            .and_then(|v| v.as_array())
            .cloned()
            .or_else(|| {
                req.get("pubkeys")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().map(|p| json!({"pub_b64": p})).collect())
            })
            .unwrap_or_default();
        if pems.is_empty() {
            return Ok(error_output(&msg, "hwbox-seal: pems/pubkeys fehlt"));
        }
        let block = match pfad(req, &self.block_path) {
            Some(v) => v.clone(),
            None => return Ok(error_output(&msg, "hwbox-seal: blockPath nicht gefunden")),
        };
        let mut boxes = Vec::new();
        for (i, p) in pems.iter().enumerate() {
            let pub_b64 = p["pub_b64"].as_str().unwrap_or_default();
            if pub_b64.is_empty() {
                return Ok(error_output(&msg, "hwbox-seal: pub_b64 fehlt"));
            }
            let pqc_pub = p["pqc_pub_b64"].as_str().unwrap_or_default();
            if pqc_pub.is_empty() {
                return Ok(error_output(
                    &msg,
                    "hwbox-seal: pqc_pub_b64 fehlt (ML-KEM-1024 Pflicht)",
                ));
            }
            let box_val = match sc::hwbox(pub_b64, pqc_pub, &block, &self.aad) {
                Ok(b) => b,
                Err(e) => return Ok(error_output(&msg, &format!("hwbox-seal: {e}"))),
            };
            let box_b64 = match sc::box_b64(&box_val) {
                Ok(b) => b,
                Err(e) => return Ok(error_output(&msg, &format!("hwbox-seal: {e}"))),
            };
            boxes.push(json!({
                "addr": pub_b64,
                "block": format!("Block-{}", i + 1),
                "box_b64": box_b64,
                "name": p["name"].clone(),
            }));
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("secretboxes".into(), json!(boxes));
        }
        Ok(ausgabe(&msg, out, "output"))
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "pemsPath" => pems_path: str,
            "blockPath" => block_path: str,
            "aad" => aad: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.pems_path, "hwbox-seal braucht pemsPath")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "hwbox-seal"
    }
}

node_factory!(HwboxSealNodeFactory, HwboxSealNode, "hwbox-seal", {
    name: "hwbox-seal".to_string(),
    pems_path: "pems".to_string(),
    block_path: "block".to_string(),
    aad: "kv3-hw".to_string(),
});
