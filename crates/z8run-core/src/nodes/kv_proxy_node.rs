//! `kv-proxy`: duenner Canvas-Node ueber der Proxy-Engine. Spricht den
//! Admin-UDS (0600) und die oeffentliche HTTP-API; keine Proxy-Logik hier.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::time::Duration;

pub struct KvProxyNode {
    name: String,
    admin_socket: String,
    action: String,
    app: String,
    input_path: String,
    db_id: String,
    sql: String,
    open_dbs: bool,
}

fn at<'a>(v: &'a Value, path: &str) -> &'a Value {
    if path.is_empty() {
        return v;
    }
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part).unwrap_or(&Value::Null);
    }
    cur
}

async fn uds_call(
    socket: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> Result<(u16, Value), String> {
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connect {socket}: {e}"))?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let bytes = body
        .map(|b| serde_json::to_vec(&b).unwrap_or_default())
        .unwrap_or_default();
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost");
    if !bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(30), sender.send_request(req))
        .await
        .map_err(|_| "proxy timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let raw = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let value = serde_json::from_slice(&raw)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&raw)}));
    Ok((status, value))
}

impl KvProxyNode {
    fn action_body(&self, payload: &Value) -> Result<Option<Value>, String> {
        match self.action.as_str() {
            "session_open" => {
                // Trigger-Payload (unix-in/http-in) traegt den Login-Body
                // unter req.body; direkter Aufruf nutzt den Payload selbst.
                let source = payload
                    .get("req")
                    .and_then(|r| r.get("body"))
                    .filter(|v| v.is_object())
                    .unwrap_or(payload);
                let mut body = source.clone();
                if let Some(o) = body.as_object_mut() {
                    o.insert("open_dbs".into(), json!(self.open_dbs));
                }
                Ok(Some(body))
            }
            "status" | "app_list" => Ok(None),
            "app_call" => Ok(Some(json!({
                "app": self.app,
                "input": at(payload, &self.input_path),
            }))),
            "db_query" => Ok(Some(json!({
                "db_id": self.db_id,
                "sql": self.sql,
                "params": [],
                "readonly": true,
            }))),
            other => Err(format!("unbekannte Aktion: {other}")),
        }
    }

    fn route(&self) -> (&'static str, String) {
        match self.action.as_str() {
            "session_open" => ("POST", "/v1/admin/session".into()),
            "status" => ("GET", "/v1/status".into()),
            "app_list" => ("GET", "/v1/apps".into()),
            "app_call" => ("POST", "/v1/app/call".into()),
            "db_query" => ("POST", "/v1/db/query".into()),
            _ => ("GET", "/v1/status".into()),
        }
    }
}

#[async_trait::async_trait]
impl NodeExecutor for KvProxyNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let (method, uri) = self.route();
        let token = at(&msg.payload, "proxy_token")
            .as_str()
            .map(|s| s.to_string());
        let body = match self.action_body(&msg.payload) {
            Ok(b) => b,
            Err(e) => {
                let mut out = msg.payload.clone();
                if let Some(o) = out.as_object_mut() {
                    o.insert("proxy_error".into(), json!(e));
                    o.remove("proxy_session");
                    o.remove("master_key_b64");
                }
                return Ok(vec![msg.derive(msg.source_node, "error", out)]);
            }
        };
        let (status, result) = match uds_call(
            &self.admin_socket,
            method,
            &uri,
            body,
            token.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let mut out = msg.payload.clone();
                if let Some(o) = out.as_object_mut() {
                    o.insert("proxy_error".into(), json!(e));
                    o.remove("proxy_session");
                    o.remove("master_key_b64");
                }
                return Ok(vec![msg.derive(msg.source_node, "error", out)]);
            }
        };
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("proxy_status".into(), json!(status));
            o.insert("proxy_result".into(), result.clone());
            if self.action == "session_open" {
                o.insert("proxy_token".into(), result["token"].clone());
                o.insert("proxy_session_id".into(), result["session_id"].clone());
                o.insert("proxy_dbs".into(), result["dbs"].clone());
            }
            // Master/Login-Body nie nach aussen spiegeln.
            o.remove("proxy_session");
            o.remove("master_key_b64");
            o.remove("master");
        }
        let port = if status == 200 { "output" } else { "error" };
        Ok(vec![msg.derive(msg.source_node, port, out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "adminSocket" => admin_socket: str,
            "action" => action: str,
            "app" => app: str,
            "inputPath" => input_path: str,
            "dbId" => db_id: str,
            "sql" => sql: str,
        );
        if let Some(v) = config.get("openDbs").and_then(|v| v.as_bool()) {
            self.open_dbs = v;
        }
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        if self.admin_socket.is_empty() {
            return Err(crate::error::Z8Error::Internal(
                "kv-proxy braucht adminSocket".into(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv-proxy"
    }
}

node_factory!(KvProxyNodeFactory, KvProxyNode, "kv-proxy", {
    name: String::new(),
    admin_socket: "/data/z8run/kv-proxy-admin.sock".to_string(),
    action: "session_open".to_string(),
    app: String::new(),
    input_path: "input".to_string(),
    db_id: String::new(),
    sql: String::new(),
    open_dbs: true,
});
