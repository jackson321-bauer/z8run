//! /secret-setzen und /secret-rotieren (Werte nie im Log, nur SHA).

use serde_json::{json, Value};

use super::setup_io::{body, S3Cfg};
use super::setup_plugin::finde_user;
use super::setup_registry as reg;
use super::setup_secret_cluster as cluster;
use super::setup_secret_db;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use rusqlite::Connection;

pub fn fehler(msg: &FlowMessage, status: u16, text: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": status, "error": text.into() }),
    )]
}

/// Lädt die secret.db eines Users aus dem "secrets"-Eintrag, führt `f` aus
/// und schreibt das Ergebnis zurück. Schreiber ist ausschließlich die
/// Setup-API; der Reader nutzt die read-only-Naht.
pub async fn mit_db<F>(
    base: &S3Cfg,
    addr: &str,
    master_hex: &str,
    out_dir: &str,
    f: F,
) -> Result<Value, String>
where
    F: FnOnce(&Connection) -> Result<Value, String>,
{
    let (profil, _text) = cluster::lade_profil(base, addr, master_hex).await?;
    let cfg = cluster::cfg_aus_profil(&profil)?;
    let bytes = cluster::lade_db(&cfg).await?;
    let dir = format!("{out_dir}/{}", profil.cluster_id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("secret tmp {dir}: {e}"))?;
    let path = std::path::PathBuf::from(format!("{dir}/secret.db"));
    std::fs::write(&path, &bytes).map_err(|e| format!("secret tmp write: {e}"))?;
    let conn = setup_secret_db::oeffne_rw(&path, &profil.db_key_hex)?;
    let ergebnis = f(&conn)?;
    setup_secret_db::checkpoint(&conn)?;
    drop(conn);
    let data = std::fs::read(&path).map_err(|e| format!("secret tmp read: {e}"))?;
    let sha = cluster::speichere_db(&cfg, &data).await?;
    let _ = std::fs::remove_file(format!("{}/secret.db-wal", dir));
    let _ = std::fs::remove_file(format!("{}/secret.db-shm", dir));
    Ok(json!({"ergebnis": ergebnis, "secret_db_sha256": sha}))
}

pub fn eintraege(req: &Value) -> Result<Vec<(String, String, String)>, String> {
    if let Some(arr) = req.get("eintraege").and_then(|v| v.as_array()) {
        let mut out = Vec::new();
        for e in arr {
            out.push((
                e["ns"].as_str().ok_or("eintrag.ns fehlt")?.to_string(),
                e["name"].as_str().ok_or("eintrag.name fehlt")?.to_string(),
                e["wert"].as_str().ok_or("eintrag.wert fehlt")?.to_string(),
            ));
        }
        return Ok(out);
    }
    Ok(vec![(
        req["ns"].as_str().ok_or("ns fehlt")?.to_string(),
        req["name"].as_str().ok_or("name fehlt")?.to_string(),
        req["wert"].as_str().ok_or("wert fehlt")?.to_string(),
    )])
}

async fn schreibe(
    msg: &FlowMessage,
    op: &str,
    s3_config: &str,
    out_dir: &str,
    rotieren: bool,
) -> Z8Result<Vec<FlowMessage>> {
    let req = body(&msg.payload);
    let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
        return Ok(fehler(msg, 403, format!("{op}: setup-auth fehlt")));
    };
    let registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
    let base = match reg::cfg_aus_registry(s3_config, req, &registry) {
        Ok(c) => c,
        Err(e) => return Ok(fehler(msg, 400, format!("{op}: {e}"))),
    };
    let Some(user) = finde_user(&registry, req) else {
        return Ok(fehler(msg, 400, format!("{op}: User nicht in Registry")));
    };
    let addr = user["addr_user"].as_str().unwrap_or_default().to_string();
    let list = match eintraege(req) {
        Ok(l) => l,
        Err(e) => return Ok(fehler(msg, 400, format!("{op}: {e}"))),
    };
    let ergebnis = mit_db(&base, &addr, master_hex, out_dir, |conn| {
        let mut out = Vec::new();
        for (ns, name, wert) in &list {
            let (sha, v) = if rotieren {
                setup_secret_db::rotieren(conn, ns, name, wert)?
            } else {
                setup_secret_db::setzen(conn, ns, name, wert)?
            };
            out.push(json!({"ns": ns, "name": name, "sha256": sha, "version": v}));
        }
        Ok(json!({"ok": true, "op": if rotieren { "rotieren" } else { "setzen" }, "eintraege": out}))
    })
    .await;
    match ergebnis {
        Ok(v) => {
            let mut out = body(&msg.payload).clone();
            if let Some(o) = out.as_object_mut() {
                o.insert("secret".into(), v);
            }
            tracing::info!(node = op, eintraege = list.len(), "secret geschrieben (nur SHA)");
            Ok(vec![msg.derive(msg.source_node, "output", out)])
        }
        Err(e) => Ok(fehler(msg, 400, format!("{op}: {e}"))),
    }
}

pub struct SecretSetzenNode {
    name: String,
    s3_config: String,
    out_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SecretSetzenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        schreibe(&msg, "secret-setzen", &self.s3_config, &self.out_dir, false).await
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
        "secret-setzen"
    }
}

node_factory!(SecretSetzenNodeFactory, SecretSetzenNode, "secret-setzen", {
    name: "secret-setzen".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    out_dir: "/tmp/z8-secrets".to_string(),
});

pub struct SecretRotierenNode {
    name: String,
    s3_config: String,
    out_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SecretRotierenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        schreibe(&msg, "secret-rotieren", &self.s3_config, &self.out_dir, true).await
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
        "secret-rotieren"
    }
}

node_factory!(SecretRotierenNodeFactory, SecretRotierenNode, "secret-rotieren", {
    name: "secret-rotieren".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    out_dir: "/tmp/z8-secrets".to_string(),
});
