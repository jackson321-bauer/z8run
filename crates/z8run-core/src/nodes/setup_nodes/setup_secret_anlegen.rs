//! /secret-anlegen: je Userspace einen secret.db-Cluster + "secrets"-Eintrag.
//! EIN Hook-Aufruf bedient N Userspaces (Z8SETUP-Muster).

use serde_json::{json, Value};

use super::setup_io::body;
use super::setup_plugin::finde_user;
use super::setup_registry as reg;
use super::setup_secret_cluster;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub struct SecretAnlegenNode {
    name: String,
    s3_config: String,
    registry_key: String,
    out_dir: String,
}

fn fehler(msg: &FlowMessage, status: u16, text: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": status, "error": text.into() }),
    )]
}

#[async_trait::async_trait]
impl NodeExecutor for SecretAnlegenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 403, "secret-anlegen: setup-auth fehlt"));
        };
        let registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
        let base = match reg::cfg_aus_registry(&self.s3_config, req, &registry) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-anlegen: {e}"))),
        };
        let space = registry["space"].as_str().unwrap_or_default().to_string();
        if space.is_empty() {
            return Ok(fehler(&msg, 400, "secret-anlegen: registry.space fehlt"));
        }
        let passwords = req.get("userPasswords").cloned().unwrap_or_else(|| json!({}));
        let namen: Vec<String> = match req.get("users").and_then(|v| v.as_array()) {
            Some(a) => a
                .iter()
                .filter_map(|u| u.as_str().map(str::to_string))
                .collect(),
            None => registry["users"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|u| u["name"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        };
        if namen.is_empty() {
            return Ok(fehler(&msg, 400, "secret-anlegen: keine Userspaces"));
        }
        let mut clusters = Vec::new();
        for name in &namen {
            let Some(user) = finde_user(&registry, &json!({"user": name})) else {
                return Ok(fehler(&msg, 400, format!("secret-anlegen: User {name} fehlt")));
            };
            let Some(pw) = passwords.get(name).and_then(|v| v.as_str()) else {
                return Ok(fehler(
                    &msg,
                    400,
                    format!("secret-anlegen: userPasswords[{name}] fehlt (ro-Profil)"),
                ));
            };
            match setup_secret_cluster::anlegen(
                &base,
                req,
                &user,
                pw,
                master_hex,
                &space,
                &self.out_dir,
            )
            .await
            {
                Ok(a) => clusters.push(a.cluster),
                Err(e) => return Ok(fehler(&msg, 400, format!("secret-anlegen: {e}"))),
            }
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert(
                "secrets_anlegen".into(),
                json!({
                    "ok": true,
                    "space": space,
                    "clusters": clusters,
                    "secrets_exposed": false,
                }),
            );
        }
        tracing::info!(node = "secret-anlegen", clusters = clusters_len(&out), "secret cluster gebaut");
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "registryKey" => registry_key: str,
            "outDir" => out_dir: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "secret-anlegen"
    }
}

fn clusters_len(out: &Value) -> usize {
    out.get("secrets_anlegen")
        .and_then(|v| v.get("clusters"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

node_factory!(SecretAnlegenNodeFactory, SecretAnlegenNode, "secret-anlegen", {
    name: "secret-anlegen".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
    out_dir: "/data/z8run-test/verify-logs/z8-setup-secretmanager/tmp".to_string(),
});
