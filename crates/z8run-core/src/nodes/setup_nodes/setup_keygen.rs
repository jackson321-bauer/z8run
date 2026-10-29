//! Setup-Node: setup-keygen (Setup-PEMs, Shamir 2-of-N, Registry initial).

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, datei_eintrag, text};
use super::setup_registry as reg;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;

fn fehler(msg: &FlowMessage, status: u16, text: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": status, "error": text.into() }),
    )]
}

// ---------------------------------------------------------------------------
// setup-keygen
// ---------------------------------------------------------------------------

pub struct SetupKeygenNode {
    name: String,
    s3_config: String,
    pem_count: usize,
    out_dir: String,
    registry_key: String,
    shards_key: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SetupKeygenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        tracing::info!(node="setup-keygen", keys=?req.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()), "setup node start");
        let cfg = match reg::cfg_aus(&self.s3_config, req) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("setup-keygen: {e}"))),
        };
        let registry_key = text(req, "registryKey").unwrap_or(&self.registry_key);
        if cfg.exists(registry_key).await {
            return Ok(fehler(
                &msg,
                409,
                "Welt bereits initialisiert — Betrieb nur mit Setup-Key (/setup nur einmal)",
            ));
        }
        let space = text(req, "space").unwrap_or_default().to_string();
        if space.is_empty() {
            return Ok(fehler(&msg, 400, "setup-keygen: space fehlt"));
        }
        let n = req
            .get("setupKeys")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(self.pem_count)
            .clamp(2, 16);
        let mut pems = Vec::new();
        for _ in 0..n {
            match sc::gen_pem() {
                Ok(p) => pems.push(p),
                Err(e) => return Ok(fehler(&msg, 500, format!("setup-keygen: {e}"))),
            }
        }
        let master: Vec<u8> = (0u8..32).map(|_| rand::random::<u8>()).collect();
        let master_hex = hex::encode(&master);
        let (shards_text, setup_keys) = match reg::shards_bauen(&master, n, &pems) {
            Ok(v) => v,
            Err(e) => return Ok(fehler(&msg, 500, format!("setup-keygen: {e}"))),
        };
        let out_dir = text(req, "keyOutDir")
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}/{}", self.out_dir, space));
        let mut pem_out = Vec::new();
        for (i, p) in pems.iter().enumerate() {
            let label = format!("setup-hw{}", i + 1);
            if let Err(e) = std::fs::create_dir_all(&out_dir) {
                return Ok(fehler(&msg, 500, format!("setup-keygen dir: {e}")));
            }
            let path = format!("{out_dir}/{label}.pem");
            if let Err(e) = std::fs::write(&path, &p.pem) {
                return Ok(fehler(&msg, 500, format!("setup-keygen write: {e}")));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            pem_out.push(json!({
                "name": label,
                "pem": p.pem,
                "pub_b64": p.pub_b64,
                "path": path,
            }));
        }
        let mut registry = sc::leeres_registry(&space);
        registry["threshold"] = json!(2);
        registry["setup_keys"] = json!(setup_keys);
        registry["s3"] = json!({
            "host": cfg.endpoint.host,
            "region": cfg.endpoint.region,
            "bucket": cfg.bucket,
            "prefix": cfg.prefix,
            "access_key": cfg.endpoint.access_key,
            "secret_key": cfg.endpoint.secret_key,
        });
        registry["quorum"] = req.get("quorum").cloned().unwrap_or(json!({"n":3,"threshold":2}));
        let registry_box = match sc::registry_siegeln(&master_hex, &registry) {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 500, format!("setup-keygen registry: {e}"))),
        };
        let registry_text = match sc::box_b64(&registry_box) {
            Ok(t) => t,
            Err(e) => return Ok(fehler(&msg, 500, format!("setup-keygen registry: {e}"))),
        };
        let shards_key = text(req, "shardsKey").unwrap_or(&self.shards_key).to_string();
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("setup_master_hex".into(), json!(master_hex));
            o.insert("setup_master_sha256".into(), json!(sc::sha_hex(&master)));
            o.insert("setup_pems".into(), json!(pem_out));
            o.insert("setup_pubkeys".into(), json!(setup_keys));
            o.insert("initialized".into(), json!(true));
            o.insert("setup_registry".into(), registry.clone());
            o.insert(
                "files".into(),
                json!([
                    datei_eintrag(shards_key, shards_text.into_bytes(), "utf8"),
                    datei_eintrag(registry_key.to_string(), registry_text.into_bytes(), "utf8"),
                ]),
            );
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "pemCount" => pem_count: usize,
            "outDir" => out_dir: str,
            "registryKey" => registry_key: str,
            "shardsKey" => shards_key: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "setup-keygen braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-keygen"
    }
}

node_factory!(SetupKeygenNodeFactory, SetupKeygenNode, "setup-keygen", {
    name: "setup-keygen".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    pem_count: 3_usize,
    out_dir: "/data/z8run/setup-keys".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
    shards_key: reg::SHARDS_KEY.to_string(),
});
