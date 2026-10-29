//! KronVault auth nodes for z8run.
//!
//! Two visible steps instead of hidden HTTP plumbing:
//!   `kv-login`  -> POST /v1/login, keeps the short-lived session token
//!   `kv-derive` -> POST /v1/derive, turns the token into a per-DB key
//!
//! Both nodes merge their result into the existing payload, so the rest of
//! the flow (S3 fetch, SQLite exec) keeps its `req`, `dbAlias` and `dbPath`.
//! Secrets are never logged; the internal header is read from a key file.

use std::time::Duration;

use serde_json::{json, Value};
use tracing::debug;

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::{error_output, require_non_empty};

fn lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn as_object(value: &Value) -> Value {
    if value.is_object() {
        value.clone()
    } else {
        json!({ "req": value.clone() })
    }
}

pub struct KvLoginNode {
    name: String,
    url: String,
    body_path: String,
    timeout_secs: u64,
}

#[async_trait::async_trait]
impl NodeExecutor for KvLoginNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let body = lookup(&msg.payload, &self.body_path)
            .cloned()
            .filter(|v| v.is_object())
            .unwrap_or_else(|| msg.payload.clone());
        if !body.is_object() {
            return Ok(error_output(&msg, "kv-login: request body is not an object"));
        }

        let client = reqwest::Client::new();
        let response = tokio::time::timeout(
            Duration::from_secs(self.timeout_secs.max(1)),
            client.post(&self.url).json(&body).send(),
        )
        .await;
        let response = match response {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Ok(error_output(&msg, &format!("kv-login: {e}"))),
            Err(_) => return Ok(error_output(&msg, "kv-login: timeout")),
        };
        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| Z8Error::Internal(format!("kv-login body: {e}")))?;
        let parsed: Value =
            serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));

        let mut out = as_object(&msg.payload);
        out["login"] = parsed.clone();
        out["loginStatus"] = json!(status);
        if let Some(token) = parsed.get("token").and_then(|v| v.as_str()) {
            out["sessionToken"] = json!(token);
        }
        debug!(node = %self.name, status, "kv-login completed");

        if status >= 400 {
            out["status"] = json!(status);
            out["error"] = parsed
                .get("error")
                .cloned()
                .unwrap_or_else(|| json!("login failed"));
            return Ok(vec![msg.derive(msg.source_node, "error", out)]);
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "url" => url: str,
            "bodyPath" => body_path: str,
            "timeoutSecs" => timeout_secs: u64,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.url, "KV Login requires a URL")?;
        require_non_empty(&self.body_path, "KV Login requires a bodyPath")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv-login"
    }
}

node_factory!(KvLoginNodeFactory, KvLoginNode, "kv-login", {
    name: String::new(),
    url: "http://127.0.0.1:7710/v1/login".to_string(),
    body_path: "req.body".to_string(),
    timeout_secs: 30
});

pub struct KvDeriveNode {
    name: String,
    url: String,
    key_file: String,
    token_path: String,
    db_path: String,
    timeout_secs: u64,
}

#[async_trait::async_trait]
impl NodeExecutor for KvDeriveNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let token = lookup(&msg.payload, &self.token_path)
            .and_then(|v| v.as_str())
            .or_else(|| lookup(&msg.payload, "login.token").and_then(|v| v.as_str()))
            .or_else(|| lookup(&msg.payload, "body.token").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        let Some(token) = token else {
            return Ok(error_output(&msg, "kv-derive: sessionToken fehlt (kv-login zuerst)"));
        };

        let db = lookup(&msg.payload, &self.db_path)
            .and_then(|v| v.as_str())
            .or_else(|| lookup(&msg.payload, "req.body.db").and_then(|v| v.as_str()))
            .or_else(|| lookup(&msg.payload, "body.db").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        let Some(db) = db else {
            return Ok(error_output(&msg, "kv-derive: db/dbAlias fehlt"));
        };

        let internal = std::fs::read_to_string(&self.key_file)
            .map_err(|e| Z8Error::Internal(format!("kv-derive key file {}: {e}", self.key_file)))?;
        let internal = internal.trim();
        if internal.is_empty() {
            return Ok(error_output(&msg, "kv-derive: key file is empty"));
        }

        let client = reqwest::Client::new();
        let response = tokio::time::timeout(
            Duration::from_secs(self.timeout_secs.max(1)),
            client
                .post(&self.url)
                .header("x-kv-internal", internal)
                .json(&json!({ "token": token, "db": db }))
                .send(),
        )
        .await;
        let response = match response {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Ok(error_output(&msg, &format!("kv-derive: {e}"))),
            Err(_) => return Ok(error_output(&msg, "kv-derive: timeout")),
        };
        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| Z8Error::Internal(format!("kv-derive body: {e}")))?;
        let parsed: Value =
            serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));

        let mut out = as_object(&msg.payload);
        out["derive"] = parsed.clone();
        out["deriveStatus"] = json!(status);
        out["dbAlias"] = json!(db);
        if let Some(s3) = parsed.get("s3") {
            out["s3"] = s3.clone();
        }
        if let Some(buckets) = parsed.get("buckets") {
            out["buckets"] = buckets.clone();
        }
        if let Some(key) = parsed.get("key_hex").and_then(|v| v.as_str()) {
            out["dbKey"] = json!(key);
        }
        debug!(node = %self.name, status, db = %db, "kv-derive completed");

        if status >= 400 {
            out["status"] = json!(status);
            out["error"] = parsed
                .get("error")
                .cloned()
                .unwrap_or_else(|| json!("derive failed"));
            return Ok(vec![msg.derive(msg.source_node, "error", out)]);
        }
        if out.get("dbKey").and_then(|v| v.as_str()).is_none() {
            return Ok(error_output(&msg, "kv-derive: Antwort ohne key_hex"));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "url" => url: str,
            "keyFile" => key_file: str,
            "tokenPath" => token_path: str,
            "dbPath" => db_path: str,
            "timeoutSecs" => timeout_secs: u64,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.url, "KV Derive requires a URL")?;
        require_non_empty(&self.key_file, "KV Derive requires a keyFile")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv-derive"
    }
}

node_factory!(KvDeriveNodeFactory, KvDeriveNode, "kv-derive", {
    name: String::new(),
    url: "http://127.0.0.1:7710/v1/derive".to_string(),
    key_file: "/etc/kv-login/internal.key".to_string(),
    token_path: "sessionToken".to_string(),
    db_path: "dbAlias".to_string(),
    timeout_secs: 30
});
