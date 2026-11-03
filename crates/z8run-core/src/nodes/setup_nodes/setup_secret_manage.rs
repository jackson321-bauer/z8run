//! /secret-revozieren (deaktivieren, nicht löschen) und /secret-liste
//! (nur Namen + Hashes; niemals Werte).

use serde_json::{json, Value};

use super::setup_io::body;
use super::setup_plugin::finde_user;
use super::setup_registry as reg;
use super::setup_secret_cluster as cluster;
use super::setup_secret_db;
use super::setup_secret_write::{fehler, mit_db};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

fn namen(req: &Value) -> Result<Vec<(String, String)>, String> {
    if let Some(arr) = req.get("eintraege").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .map(|e| {
                Ok((
                    e["ns"].as_str().ok_or("eintrag.ns fehlt")?.to_string(),
                    e["name"].as_str().ok_or("eintrag.name fehlt")?.to_string(),
                ))
            })
            .collect();
    }
    Ok(vec![(
        req["ns"].as_str().ok_or("ns fehlt")?.to_string(),
        req["name"].as_str().ok_or("name fehlt")?.to_string(),
    )])
}

pub struct SecretRevozierenNode {
    name: String,
    s3_config: String,
    out_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SecretRevozierenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 403, "secret-revozieren: setup-auth fehlt"));
        };
        let registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
        let base = match reg::cfg_aus_registry(&self.s3_config, req, &registry) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-revozieren: {e}"))),
        };
        let Some(user) = finde_user(&registry, req) else {
            return Ok(fehler(&msg, 400, "secret-revozieren: User nicht in Registry"));
        };
        let addr = user["addr_user"].as_str().unwrap_or_default().to_string();
        let liste = match namen(req) {
            Ok(l) => l,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-revozieren: {e}"))),
        };
        let r = mit_db(&base, &addr, master_hex, &self.out_dir, |conn| {
            let mut out = Vec::new();
            for (ns, name) in &liste {
                let (sha, v) = setup_secret_db::revozieren(conn, ns, name)?;
                out.push(json!({"ns": ns, "name": name, "sha256": sha, "version": v, "aktiv": false}));
            }
            Ok(json!({"ok": true, "op": "revozieren", "eintraege": out}))
        })
        .await;
        match r {
            Ok(v) => {
                let mut out = body(&msg.payload).clone();
                if let Some(o) = out.as_object_mut() {
                    o.insert("secret".into(), v);
                }
                tracing::info!(node = "secret-revozieren", eintraege = liste.len(), "secret deaktiviert");
                Ok(vec![msg.derive(msg.source_node, "output", out)])
            }
            Err(e) => Ok(fehler(&msg, 400, format!("secret-revozieren: {e}"))),
        }
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str, "s3Config" => s3_config: str, "outDir" => out_dir: str);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }
    fn node_type(&self) -> &str {
        "secret-revozieren"
    }
}

node_factory!(SecretRevozierenNodeFactory, SecretRevozierenNode, "secret-revozieren", {
    name: "secret-revozieren".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    out_dir: "/tmp/z8-secrets".to_string(),
});

pub struct SecretListeNode {
    name: String,
    s3_config: String,
    out_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SecretListeNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 403, "secret-liste: setup-auth fehlt"));
        };
        let registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
        let base = match reg::cfg_aus_registry(&self.s3_config, req, &registry) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-liste: {e}"))),
        };
        let Some(user) = finde_user(&registry, req) else {
            return Ok(fehler(&msg, 400, "secret-liste: User nicht in Registry"));
        };
        let addr = user["addr_user"].as_str().unwrap_or_default().to_string();
        let (profil, _) = match cluster::lade_profil(&base, &addr, master_hex).await {
            Ok(p) => p,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-liste: {e}"))),
        };
        let cfg = match cluster::cfg_aus_profil(&profil) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-liste: {e}"))),
        };
        let bytes = match cluster::lade_db(&cfg).await {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-liste: {e}"))),
        };
        let dir = format!("{}/{}", self.out_dir, profil.cluster_id);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return Ok(fehler(&msg, 400, format!("secret-liste: {e}")));
        }
        let path = std::path::PathBuf::from(format!("{dir}/secret.db"));
        if let Err(e) = std::fs::write(&path, &bytes) {
            return Ok(fehler(&msg, 400, format!("secret-liste: {e}")));
        }
        let conn = match setup_secret_db::oeffne_readonly(&path, &profil.db_key_hex) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-liste: {e}"))),
        };
        let eintraege = match setup_secret_db::liste(&conn) {
            Ok(l) => l,
            Err(e) => return Ok(fehler(&msg, 400, format!("secret-liste: {e}"))),
        };
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert(
                "secret".into(),
                json!({"ok": true, "op": "liste", "eintraege": eintraege,
                       "secrets_exposed": false}),
            );
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str, "s3Config" => s3_config: str, "outDir" => out_dir: str);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }
    fn node_type(&self) -> &str {
        "secret-liste"
    }
}

node_factory!(SecretListeNodeFactory, SecretListeNode, "secret-liste", {
    name: "secret-liste".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    out_dir: "/tmp/z8-secrets".to_string(),
});
