//! setup-world: initiale Welt (mehrere lokale Userspaces, KEIN Shared — D6).

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, datei_bytes, datei_eintrag, fehler, text};
use super::setup_registry as reg;
use super::setup_world_build::bau_user;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::utils::node_helpers::require_non_empty;

pub struct SetupWorldNode {
    pub(crate) name: String,
    pub(crate) s3_config: String,
    pub(crate) out_dir: String,
    pub(crate) vec0_path: String,
    pub(crate) hw_keys: usize,
    pub(crate) registry_key: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SetupWorldNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        tracing::info!(node="setup-world", keys=?req.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()), "setup node start");
        let cfg = match reg::cfg_aus(&self.s3_config, req) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, format!("setup-world: {e}"))),
        };
        let Some(master_hex) = text(req, "setup_master_hex") else {
            return Ok(fehler(&msg, "setup-world: setup-keygen fehlt"));
        };
        let space = text(req, "space").unwrap_or_default().to_string();
        if space.is_empty() {
            return Ok(fehler(&msg, "setup-world: space fehlt"));
        }
        let registry_key = text(req, "registryKey").unwrap_or(&self.registry_key).to_string();
        let mut registry = match req.get("setup_registry") {
            Some(v) if v.is_object() => v.clone(),
            _ => match reg::lade_registry(&cfg, &registry_key, master_hex).await {
                Ok(r) => r,
                Err(e) => return Ok(fehler(&msg, format!("setup-world registry: {e}"))),
            },
        };
        if registry["space"].as_str() != Some(space.as_str()) {
            return Ok(fehler(&msg, "setup-world: Registry gehört zu anderem Space"));
        }
        let Some(users) = req.get("users").and_then(|v| v.as_array()) else {
            return Ok(fehler(&msg, "setup-world: users[] fehlt"));
        };
        let base = text(req, "keyOutDir")
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}/{}", self.out_dir, space));
        let key_dir = format!("{base}/users");
        let db_dir = text(req, "dbOutDir")
            .map(str::to_string)
            .unwrap_or_else(|| format!("{base}/db"));
        let vec0 = text(req, "vec0Path").unwrap_or(&self.vec0_path).to_string();
        let hw = req
            .get("hwKeys")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(self.hw_keys)
            .clamp(1, 8);

        let mut files: Vec<Value> = req
            .get("files")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter(|e| e["key"].as_str() != Some(registry_key.as_str()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut users_out = Vec::new();
        let mut reg_users = Vec::new();
        let db_oeffentlich = |db: &Value| {
            let mut d = db.clone();
            for name in ["demo", "meta"] {
                if let Some(o) = d.get_mut(name).and_then(|v| v.as_object_mut()) {
                    o.remove("key_hex");
                }
            }
            d
        };
        for u in users {
            let b = match bau_user(
                &cfg.prefix, &space, u, &key_dir, &db_dir, &vec0, hw, master_hex,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => return Ok(fehler(&msg, format!("setup-world: {e}"))),
            };
            for f in &b.files {
                files.push(f.clone());
            }
            let pubkeys: Vec<Value> = b
                .pems
                .iter()
                .map(|p| {
                    json!({
                        "name": p["name"],
                        "pub_b64": p["pub_b64"],
                        "pqc_pub_b64": p["pqc_pub_b64"],
                        "path": p["path"],
                    })
                })
                .collect();
            let user_json = json!({
                "name": b.name,
                "addr_user": b.addr,
                "user_master_sha256": b.master_sha256,
                "workspace_bucket": b.block["workspace_bucket"],
                "engines": b.block["engines"],
                "db": db_oeffentlich(&b.db),
                "pubkeys": pubkeys,
                "pems": b.pems.iter().map(|p| json!({
                    "name": p["name"], "pub_b64": p["pub_b64"],
                    "pqc_pub_b64": p["pqc_pub_b64"],
                    "path": p["path"], "pqc_dk_path": p["pqc_dk_path"]
                })).collect::<Vec<_>>(),
            });
            users_out.push(user_json.clone());
            reg_users.push(json!({
                "name": b.name,
                "addr_user": b.addr,
                "user_master_sha256": b.master_sha256,
                "workspace_bucket": b.block["workspace_bucket"],
                "engines": b.block["engines"],
                "pubkeys": pubkeys,
                "db": db_oeffentlich(&b.db),
            }));
        }

        let addr_space = match sc::kette::adresse(&space, &sc::salt_space(&space)) {
            Ok(a) => a,
            Err(e) => return Ok(fehler(&msg, format!("setup-world: {e}"))),
        };
        registry["space_addr"] = json!(addr_space);
        registry["users"] = json!(reg_users);
        registry["multi_user"] = json!(users.len() > 1);
        registry["shared"] = json!(false);
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        let registry_box = match sc::registry_siegeln(master_hex, &registry) {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, format!("setup-world registry: {e}"))),
        };
        let registry_text = match sc::box_b64(&registry_box) {
            Ok(t) => t,
            Err(e) => return Ok(fehler(&msg, format!("setup-world registry: {e}"))),
        };
        files.push(datei_eintrag(registry_key, registry_text.into_bytes(), "utf8"));

        let dateien: Vec<Value> = files
            .iter()
            .map(|f| {
                let bytes = datei_bytes(f).map(|d| d.len()).unwrap_or(0);
                json!({
                    "key": f["key"],
                    "sha256": f["sha256"],
                    "bytes": bytes,
                })
            })
            .collect();
        let world = json!({
            "ok": true,
            "space": space,
            "addr_space": addr_space,
            "shared": false,
            "users": users_out,
            "setup_pubkeys": registry["setup_keys"],
            "files": dateien,
        });
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("users".into(), json!(users_out));
            o.remove("setup_registry");
            o.insert("files".into(), json!(files));
            o.insert("world".into(), world);
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "outDir" => out_dir: str,
            "vec0Path" => vec0_path: str,
            "hwKeys" => hw_keys: usize,
            "registryKey" => registry_key: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "setup-world braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-world"
    }
}

