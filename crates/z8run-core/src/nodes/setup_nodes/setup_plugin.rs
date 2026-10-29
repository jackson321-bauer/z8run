//! /plugin-add: Plugin-Freigabe NUR mit Setup-Key (D5).
//! Der Setup-Block liegt in DERSELBEN Hashdatei, ist aber mit dem Setup-Master
//! versiegelt — der User-Block bleibt unberührt.

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::body;
use super::setup_registry as reg;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub const PLUGIN_SALT: &str = "kv3-setup-plugins";

pub struct PluginAddNode {
    name: String,
    s3_config: String,
    registry_key: String,
}

fn fehler(msg: &FlowMessage, status: u16, text: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({ "status": status, "error": text.into() }),
    )]
}

pub fn finde_user(registry: &Value, req: &Value) -> Option<Value> {
    let addr = req.get("user_addr").and_then(|v| v.as_str());
    let name = req.get("user").and_then(|v| v.as_str());
    registry["users"].as_array()?.iter().find_map(|u| {
        let ok = match (addr, name) {
            (Some(a), _) => u["addr_user"] == json!(a),
            (None, Some(n)) => u["name"] == json!(n),
            _ => false,
        };
        if ok { Some(u.clone()) } else { None }
    })
}

#[async_trait::async_trait]
impl NodeExecutor for PluginAddNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 403, "plugin-add: setup-auth fehlt"));
        };
        let Some(plugin) = req.get("plugin").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 400, "plugin-add: plugin fehlt"));
        };
        let mut registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
        let cfg = match reg::cfg_aus_registry(&self.s3_config, req, &registry) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("plugin-add: {e}"))),
        };
        let Some(user) = finde_user(&registry, req) else {
            return Ok(fehler(&msg, 400, "plugin-add: User nicht in Registry"));
        };
        let addr = user["addr_user"].as_str().unwrap_or_default().to_string();
        let key = format!("b2b/{addr}.txt");
        let text = match cfg.get(&key).await {
            Ok(d) => String::from_utf8_lossy(&d).to_string(),
            Err(e) => return Ok(fehler(&msg, 400, format!("plugin-add: {e}"))),
        };
        let (addrs, blocks) = sc::hashdatei_parsen(&text);
        let setup_addr = format!("setup-plugins-{addr}");
        let map: std::collections::HashMap<String, String> = blocks.into_iter().collect();
        let mut plugins: Vec<String> = Vec::new();
        if let Some(block_name) = addrs.iter().find(|(a, _)| a == &setup_addr).map(|(_, b)| b.clone()) {
            if let Some(chiffre) = map.get(&block_name) {
                if let Ok(box_val) = sc::box_aus_b64(chiffre) {
                    if let Ok(plain) = sc::passbox_oeffne(&box_val, master_hex, PLUGIN_SALT) {
                        plugins = plain["plugins"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect())
                            .unwrap_or_default();
                    }
                }
            }
        }
        if !plugins.iter().any(|p| p == plugin) {
            plugins.push(plugin.to_string());
        }
        let block = json!({"plugins": plugins, "approved_by": "setup-key"});
        let box_val = match sc::passbox(master_hex, PLUGIN_SALT, &block, PLUGIN_SALT) {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 400, format!("plugin-add: {e}"))),
        };
        let box_b64 = match sc::box_b64(&box_val) {
            Ok(b) => b,
            Err(e) => return Ok(fehler(&msg, 400, format!("plugin-add: {e}"))),
        };
        let mut new_addrs: Vec<(String, String)> = Vec::new();
        let mut new_chiffren: Vec<(String, String)> = Vec::new();
        let mut ersetzt = false;
        for (a, b) in &addrs {
            if a == &setup_addr {
                new_addrs.push((a.clone(), b.clone()));
                new_chiffren.push((b.clone(), box_b64.clone()));
                ersetzt = true;
            } else {
                new_addrs.push((a.clone(), b.clone()));
                if let Some(c) = map.get(b) {
                    new_chiffren.push((b.clone(), c.clone()));
                }
            }
        }
        if !ersetzt {
            let block_name = format!("Block-{}", addrs.len() + 1);
            new_addrs.push((setup_addr, block_name.clone()));
            new_chiffren.push((block_name, box_b64));
        }
        let neu = sc::hashdatei_bauen(&new_addrs, &new_chiffren);
        let sha = sc::sha_hex(neu.as_bytes());
        if let Err(e) = cfg.put(&key, neu.into_bytes()).await {
            return Ok(fehler(&msg, 400, format!("plugin-add put: {e}")));
        }

        if !registry["plugins"].is_object() {
            registry["plugins"] = json!({});
        }
        registry["plugins"][&addr] = json!(plugins);
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        if let Err(e) = reg::speichere_registry(&cfg, &self.registry_key, master_hex, &registry).await {
            return Ok(fehler(&msg, 400, format!("plugin-add registry: {e}")));
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("setup_registry".into(), registry);
            o.insert("plugin".into(), json!({
                "ok": true, "user_addr": addr, "plugins": plugins,
                "hashdatei_key": key, "hashdatei_sha256": sha,
            }));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "registryKey" => registry_key: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "plugin-add"
    }
}

node_factory!(PluginAddNodeFactory, PluginAddNode, "plugin-add", {
    name: "plugin-add".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
});
