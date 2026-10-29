//! /rotate-s3: neue S3-Endpunkte, Hashdateien/Boxen mitnehmen.
//! Shards + Salts bleiben unverändert → Login mit altem PW/PEM bleibt gültig.

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::{body, S3Cfg};
use super::setup_registry as reg;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub struct RotateS3Node {
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

#[async_trait::async_trait]
impl NodeExecutor for RotateS3Node {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(master_hex) = req.get("setup_master_hex").and_then(|v| v.as_str()) else {
            return Ok(fehler(&msg, 403, "rotate-s3: setup-auth fehlt"));
        };
        let registry = req.get("setup_registry").cloned().unwrap_or_else(|| json!({}));
        let old = match reg::cfg_aus_registry(&self.s3_config, req, &registry) {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("rotate-s3: {e}"))),
        };
        if old.prefix.is_empty() {
            return Ok(fehler(&msg, 400, "rotate-s3: alter prefix fehlt"));
        }
        let Some(new_s3) = req.get("newS3") else {
            return Ok(fehler(&msg, 400, "rotate-s3: newS3 fehlt"));
        };
        let new: S3Cfg = match S3Cfg::aus_datei(&self.s3_config)
            .and_then(|c| c.mit_override(&registry["s3"]))
            .and_then(|c| c.mit_override(new_s3))
        {
            Ok(c) => c,
            Err(e) => return Ok(fehler(&msg, 400, format!("rotate-s3: {e}"))),
        };
        if new.bucket.is_empty() || new.prefix.is_empty() {
            return Ok(fehler(&msg, 400, "rotate-s3: newS3 bucket/prefix fehlt"));
        }
        if new.bucket == old.bucket
            && new.prefix == old.prefix
            && new.endpoint.host == old.endpoint.host
            && new.endpoint.access_key == old.endpoint.access_key
        {
            return Ok(fehler(&msg, 400, "rotate-s3: Ziel identisch mit Quelle"));
        }

        let objects = match old.list("").await {
            Ok(o) => o,
            Err(e) => return Ok(fehler(&msg, 400, format!("rotate-s3: {e}"))),
        };
        let mut kopiert = Vec::new();
        for (key, size) in objects {
            let Some(rel) = key.strip_prefix(old.prefix.as_str()) else {
                continue;
            };
            if rel == self.registry_key {
                continue; // Registry wird nach dem Update neu geschrieben.
            }
            let data = match old.get(rel).await {
                Ok(d) => d,
                Err(e) => return Ok(fehler(&msg, 400, format!("rotate-s3 get {rel}: {e}"))),
            };
            let sha = sc::sha_hex(&data);
            if let Err(e) = new.put(rel, data).await {
                return Ok(fehler(&msg, 400, format!("rotate-s3 put {rel}: {e}")));
            }
            kopiert.push(json!({"key": rel, "bytes": size, "sha256": sha}));
        }
        if kopiert.is_empty() {
            return Ok(fehler(&msg, 400, "rotate-s3: keine Objekte unter altem Prefix"));
        }

        // D4: optional echte Neuversiegelung der Boxen (Shards+Salts bleiben).
        let mut resealed = Vec::new();
        if req.get("rotateBoxes").and_then(|v| v.as_bool()).unwrap_or(false) {
            let Some(pw) = req.get("userPasswords") else {
                return Ok(fehler(&msg, 400, "rotate-s3: rotateBoxes braucht userPasswords"));
            };
            match super::setup_rotate_reseal::reseal(&new, &registry, master_hex, pw).await {
                Ok(r) => resealed = r,
                Err(e) => return Ok(fehler(&msg, 400, format!("rotate-s3 reseal: {e}"))),
            }
        }

        let mut registry = registry;
        registry["rotation"] = json!({
            "at": chrono::Utc::now().to_rfc3339(),
            "from": {"bucket": old.bucket, "prefix": old.prefix, "host": old.endpoint.host},
            "to": {"bucket": new.bucket, "prefix": new.prefix, "host": new.endpoint.host},
            "objects": kopiert.len(),
            "shards_salts_unchanged": true,
            "resealed": resealed.len(),
            "resealed_changed": resealed.iter().all(|r| r["before"] != r["after"]),
        });
        registry["s3"] = json!({
            "host": new.endpoint.host,
            "region": new.endpoint.region,
            "bucket": new.bucket,
            "prefix": new.prefix,
            "access_key": new.endpoint.access_key,
            "secret_key": new.endpoint.secret_key,
        });
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        let reg_sha = match reg::speichere_registry(&new, &self.registry_key, master_hex, &registry).await {
            Ok(s) => s,
            Err(e) => return Ok(fehler(&msg, 400, format!("rotate-s3 registry: {e}"))),
        };

        let delete_old = req.get("deleteOld").and_then(|v| v.as_bool()).unwrap_or(false);
        let mut geloescht = 0usize;
        if delete_old {
            for (key, _) in old.list("").await.unwrap_or_default() {
                let rel = key.strip_prefix(old.prefix.as_str()).unwrap_or(&key).to_string();
                if old.delete(&rel).await.is_ok() {
                    geloescht += 1;
                }
            }
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("setup_registry".into(), registry);
            o.insert("rotation".into(), json!({
                "ok": true,
                "objects": kopiert.len(),
                "deleted_old": geloescht,
                "from_prefix": old.prefix,
                "to_prefix": new.prefix,
                "registry_sha256": reg_sha,
                "shards_salts_unchanged": true,
                "resealed": resealed.len(),
                "resealed_changed": resealed.iter().all(|r| r["before"] != r["after"]),
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
        "rotate-s3"
    }
}

node_factory!(RotateS3NodeFactory, RotateS3Node, "rotate-s3", {
    name: "rotate-s3".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
});
