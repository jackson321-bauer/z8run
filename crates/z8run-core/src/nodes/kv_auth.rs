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
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
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

/// HTTP-Semantik ueber den internen UDS (udsv3). `uds:///pfad.sock/v1/x`
/// bleibt intern; eine http(s)-URL nutzt den Legacy-Client.
async fn post_json(
    url: &str,
    body: &Value,
    headers: &[(&str, &str)],
    timeout_secs: u64,
) -> Result<(u16, Value), String> {
    if let Some(rest) = url.strip_prefix("uds://") {
        let (sock, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let run = async {
            let stream = crate::udsv3_stream::connect(std::path::Path::new(sock), "kv-login")
                .map_err(|e| format!("udsv3 {sock}: {e}"))?;
            let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
            let mut builder = hyper::Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "localhost")
                .header("content-type", "application/json");
            for (k, v) in headers {
                builder = builder.header(*k, *v);
            }
            let req = builder
                .body(Full::new(Bytes::from(bytes)))
                .map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let raw = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            let value = serde_json::from_slice(&raw)
                .unwrap_or_else(|_| serde_json::json!({"raw": String::from_utf8_lossy(&raw)}));
            Ok::<_, String>((status, value))
        };
        return tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), run)
            .await
            .map_err(|_| "timeout".to_string())?;
    }
    Err("nur uds://... erlaubt (Gateway-Gesetz; kein Direkt-HTTP)".to_string())
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
            return Ok(error_output(
                &msg,
                "kv-login: request body is not an object",
            ));
        }

        let (status, parsed) = match post_json(&self.url, &body, &[], self.timeout_secs).await {
            Ok(v) => v,
            Err(e) => return Ok(error_output(&msg, &format!("kv-login: {e}"))),
        };

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
    url: "uds:///data/z8run/kv-login.sock/v1/login".to_string(),
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
            return Ok(error_output(
                &msg,
                "kv-derive: sessionToken fehlt (kv-login zuerst)",
            ));
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

        let (status, parsed) = match post_json(
            &self.url,
            &json!({ "token": token, "db": db }),
            &[("x-kv-internal", internal)],
            self.timeout_secs,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => return Ok(error_output(&msg, &format!("kv-derive: {e}"))),
        };

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
    url: "uds:///data/z8run/kv-login.sock/v1/derive".to_string(),
    key_file: "/etc/kv-login/internal.key".to_string(),
    token_path: "sessionToken".to_string(),
    db_path: "dbAlias".to_string(),
    timeout_secs: 30
});
