//! Setup-Nodes S1: pem-gen + shamir-split2 (Schlüssel/Anteile).
//! Dünne Verkabelung — Krypto und Formate kommen aus `setup_crypto`/`kette`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, text};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
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
// pem-gen
// ---------------------------------------------------------------------------

pub struct PemGenNode {
    name: String,
    count: usize,
    prefix: String,
    out_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for PemGenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let count = req
            .get("count")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(self.count)
            .max(1);
        let prefix = text(req, "prefix").unwrap_or(&self.prefix).to_string();
        let out_dir = text(req, "outDir").unwrap_or(&self.out_dir).to_string();
        let mut pems = Vec::new();
        for i in 1..=count {
            let paar = match sc::gen_pem() {
                Ok(p) => p,
                Err(e) => return Ok(error_output(&msg, &format!("pem-gen: {e}"))),
            };
            let label = format!("{prefix}-hw{i}");
            let mut eintrag = json!({
                "name": label,
                "pem": paar.pem,
                "pub_b64": paar.pub_b64,
            });
            if !out_dir.is_empty() {
                let dir = std::path::Path::new(&out_dir);
                std::fs::create_dir_all(dir)
                    .map_err(|e| Z8Error::Internal(format!("pem-gen dir {out_dir}: {e}")))?;
                let path = dir.join(format!("{label}.pem"));
                std::fs::write(&path, &paar.pem)
                    .map_err(|e| Z8Error::Internal(format!("pem-gen write {path:?}: {e}")))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                eintrag["path"] = json!(path.to_string_lossy());
            }
            pems.push(eintrag);
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            if pems.len() == 1 {
                o.insert("pem".into(), pems[0]["pem"].clone());
                o.insert("pub_b64".into(), pems[0]["pub_b64"].clone());
            }
            o.insert("pems".into(), json!(pems));
        }
        Ok(ausgabe(&msg, out, "output"))
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "count" => count: usize,
            "prefix" => prefix: str,
            "outDir" => out_dir: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "pem-gen"
    }
}

node_factory!(PemGenNodeFactory, PemGenNode, "pem-gen", {
    name: String::new(),
    count: 1_usize,
    prefix: "key".to_string(),
    out_dir: String::new(),
});

// ---------------------------------------------------------------------------
// shamir-split2
// ---------------------------------------------------------------------------

pub struct ShamirSplit2Node {
    name: String,
    shares: usize,
    emit_master: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for ShamirSplit2Node {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let n = req
            .get("shares")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(self.shares)
            .max(2);
        let master: Vec<u8> = match text(req, "master_hex") {
            Some(h) if !h.is_empty() => match hex::decode(h) {
                Ok(m) if m.len() == 32 => m,
                _ => return Ok(error_output(&msg, "shamir-split2: master_hex muss 64 Hex sein")),
            },
            _ => (0u8..32).map(|_| rand::random::<u8>()).collect(),
        };
        let xs: Vec<u8> = (1..=n).map(|i| i as u8).collect();
        let shares = match sc::kette::shamir::split2(&master, &xs) {
            Ok(s) => s,
            Err(e) => return Ok(error_output(&msg, &format!("shamir-split2: {e}"))),
        };
        let emit = req
            .get("emitMaster")
            .and_then(|v| v.as_bool())
            .unwrap_or(self.emit_master);
        let liste: Vec<Value> = shares
            .iter()
            .map(|s| json!({ "x": s.x, "y_b64": B64.encode(&s.y) }))
            .collect();
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("shares".into(), json!(liste));
            o.insert("master_sha256".into(), json!(sc::sha_hex(&master)));
            if emit {
                o.insert(
                    "master_hex".into(),
                    json!(hex::encode(&master)),
                );
            }
        }
        Ok(ausgabe(&msg, out, "output"))
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "shares" => shares: usize,
            "emitMaster" => emit_master: bool,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.name, "shamir-split2 braucht name")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "shamir-split2"
    }
}

node_factory!(ShamirSplit2NodeFactory, ShamirSplit2Node, "shamir-split2", {
    name: "shamir-split2".to_string(),
    shares: 2_usize,
    emit_master: false,
});

