//! Unix Out node: HTTP/1.1 client over a local Unix domain socket.
//!
//! Same request/response contract as `http-request`, but the transport is a
//! Unix socket instead of TCP. No TLS: the socket never leaves the machine;
//! access is controlled by filesystem permissions and SO_PEERCRED.
//!
//! Outputs:
//!   - "output" port: `{ status, headers, body, socketPath, path }`
//!   - "error" port: connect/timeout/protocol errors

use super::switch::json_path_lookup;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::time::Duration;
use tokio::net::UnixStream;
use tracing::{info, warn};

/// Regex for `{path.to.field}` placeholders in the request path.
fn resolve_template(template: &str, data: &serde_json::Value) -> String {
    let re = regex::Regex::new(r"\{([^}]+)\}").unwrap();
    re.replace_all(template, |caps: &regex::Captures| {
        let path = &caps[1];
        let val = json_path_lookup(data, path);
        match &val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            other => other.to_string().trim_matches('"').to_string(),
        }
    })
    .to_string()
}

/// Log-safe path: drop query/fragment so tokens never reach the logs.
fn sanitize_path(path: &str) -> String {
    path.split(['?', '#']).next().unwrap_or(path).to_string()
}

pub struct UnixOutNode {
    name: String,
    socket_path: String,
    method: String,
    path: String,
    headers: serde_json::Value,
    body_path: String,
    timeout_ms: u64,
    max_response_bytes: u64,
}

impl UnixOutNode {
    fn error_output(&self, msg: &FlowMessage, error: &str, timeout: bool) -> FlowMessage {
        warn!(
            node = %self.name,
            error = %error,
            socket = %self.socket_path,
            path = %sanitize_path(&self.path),
            "Unix Out failed"
        );
        let payload = serde_json::json!({
            "error": error,
            "socketPath": self.socket_path,
            "path": self.path,
            "timeout": timeout,
        });
        msg.derive(msg.source_node, "error", payload)
    }
}

#[async_trait::async_trait]
impl NodeExecutor for UnixOutNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let method = match self.method.as_str() {
            "POST" => hyper::Method::POST,
            "PUT" => hyper::Method::PUT,
            "PATCH" => hyper::Method::PATCH,
            "DELETE" => hyper::Method::DELETE,
            "HEAD" => hyper::Method::HEAD,
            _ => hyper::Method::GET,
        };

        let resolved_path = resolve_template(&self.path, &msg.payload);
        let path_and_query = if resolved_path.starts_with('/') {
            resolved_path.clone()
        } else {
            format!("/{resolved_path}")
        };

        let uri = match hyper::Uri::builder()
            .scheme("http")
            .authority("localhost")
            .path_and_query(path_and_query)
            .build()
        {
            Ok(uri) => uri,
            Err(e) => {
                return Ok(vec![self.error_output(&msg, &e.to_string(), false)]);
            }
        };

        let body_value = if !self.body_path.is_empty()
            && self.method != "GET"
            && self.method != "HEAD"
        {
            json_path_lookup(&msg.payload, &self.body_path)
        } else {
            serde_json::Value::Null
        };
        let body_bytes = if body_value.is_null() {
            Vec::new()
        } else {
            match serde_json::to_vec(&body_value) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Ok(vec![self.error_output(&msg, &e.to_string(), false)]);
                }
            }
        };

        let mut builder = hyper::Request::builder()
            .method(method.clone())
            .uri(uri)
            .header("host", "localhost");
        if !body_bytes.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        if let serde_json::Value::Object(headers) = &self.headers {
            for (key, value) in headers {
                if let Some(val_str) = value.as_str() {
                    builder = builder.header(key.as_str(), val_str);
                }
            }
        }

        let request = match builder.body(Full::new(Bytes::from(body_bytes))) {
            Ok(request) => request,
            Err(e) => {
                return Ok(vec![self.error_output(&msg, &e.to_string(), false)]);
            }
        };

        info!(
            node = %self.name,
            method = %self.method,
            socket = %self.socket_path,
            path = %sanitize_path(&resolved_path),
            "Unix Out request"
        );

        let socket_path = self.socket_path.clone();
        let timeout_ms = self.timeout_ms;
        let max_body = self.max_response_bytes;
        let outcome = tokio::time::timeout(Duration::from_millis(timeout_ms), async move {
            let stream = UnixStream::connect(&socket_path)
                .await
                .map_err(|e| e.to_string())?;
            let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let headers: serde_json::Map<String, serde_json::Value> = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|v| (name.to_string(), serde_json::Value::String(v.to_string())))
                })
                .collect();
            let body = Limited::new(response.into_body(), max_body as usize)
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(
                if body.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(String::from_utf8_lossy(&body).to_string())
                },
            );
            Ok::<(u16, serde_json::Map<String, serde_json::Value>, serde_json::Value), String>((
                status,
                headers,
                body_json,
            ))
        })
        .await;

        match outcome {
            Err(_) => Ok(vec![self.error_output(&msg, "timeout", true)]),
            Ok(Err(error)) => Ok(vec![self.error_output(&msg, &error, false)]),
            Ok(Ok((status, headers, body))) => {
                info!(node = %self.name, status = status, "Unix Out completed");
                let payload = serde_json::json!({
                    "status": status,
                    "headers": headers,
                    "body": body,
                    "socketPath": self.socket_path,
                    "path": resolved_path,
                });
                Ok(vec![msg.derive(msg.source_node, "output", payload)])
            }
        }
    }

    async fn configure(&mut self, config: serde_json::Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "socketPath" => socket_path: str,
            "method" => method: str_upper,
            "path" => path: str,
            "bodyPath" => body_path: str,
            "timeout" => timeout_ms: u64,
            "maxResponseBytes" => max_response_bytes: u64,
            "headers" => headers: value,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.socket_path, "Unix Out node requires a socketPath")?;
        require_non_empty(&self.path, "Unix Out node requires a path")?;
        if !std::path::Path::new(&self.socket_path).is_absolute() {
            return Err(crate::error::Z8Error::Internal(
                "Unix Out socketPath must be an absolute path".to_string(),
            ));
        }
        if !matches!(
            self.method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
        ) {
            return Err(crate::error::Z8Error::Internal(format!(
                "Unix Out method '{}' is not supported",
                self.method
            )));
        }
        if self.max_response_bytes == 0 {
            return Err(crate::error::Z8Error::Internal(
                "Unix Out maxResponseBytes must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "unix-out"
    }
}

node_factory!(UnixOutNodeFactory, UnixOutNode, "unix-out", {
    name: "Unix Out".to_string(),
    socket_path: "/data/z8run/z8run.sock".to_string(),
    method: "POST".to_string(),
    path: "/".to_string(),
    headers: serde_json::json!({}),
    body_path: "payload".to_string(),
    timeout_ms: 5000,
    max_response_bytes: 10_485_760
});

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use uuid::Uuid;

    fn test_msg(payload: serde_json::Value) -> FlowMessage {
        FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7())
    }

    fn test_node(socket_path: &str, path: &str, timeout_ms: u64) -> UnixOutNode {
        UnixOutNode {
            name: "Unix Out".to_string(),
            socket_path: socket_path.to_string(),
            method: "POST".to_string(),
            path: path.to_string(),
            headers: serde_json::json!({}),
            body_path: String::new(),
            timeout_ms,
            max_response_bytes: 10_485_760,
        }
    }

    /// Minimal HTTP/1.1 server on a Unix socket. It reads one request and
    /// writes one fixed response. No z8run engine, no database, no UI.
    async fn serve_once(path: std::path::PathBuf, response: &'static [u8]) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).expect("bind test socket");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf).await;
            stream.write_all(response).await.expect("write response");
            stream.flush().await.expect("flush");
        })
    }

    #[tokio::test]
    async fn roundtrip_returns_status_and_json_body() {
        let path = std::env::temp_dir().join(format!("z8-uds-ok-{}.sock", Uuid::now_v7()));
        let _ = std::fs::remove_file(&path);
        let handle = serve_once(
            path.clone(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        )
        .await;

        let node = test_node(path.to_str().unwrap(), "/echo", 5000);
        let out = node.process(test_msg(serde_json::json!({"x": 1}))).await.unwrap();
        handle.await.unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source_port, "output");
        assert_eq!(out[0].payload["status"], 200);
        assert_eq!(out[0].payload["body"]["ok"], true);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn missing_socket_lands_on_error_port() {
        let path = std::env::temp_dir().join(format!("z8-uds-missing-{}.sock", Uuid::now_v7()));
        let _ = std::fs::remove_file(&path);
        let node = test_node(path.to_str().unwrap(), "/echo", 500);

        let out = node.process(test_msg(serde_json::json!({}))).await.unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source_port, "error");
        let err = out[0].payload["error"].as_str().unwrap();
        assert!(err.contains("No such file"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn timeout_lands_on_error_port() {
        let path = std::env::temp_dir().join(format!("z8-uds-timeout-{}.sock", Uuid::now_v7()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let node = test_node(path.to_str().unwrap(), "/echo", 50);
        let out = node.process(test_msg(serde_json::json!({}))).await.unwrap();
        handle.abort();
        let _ = std::fs::remove_file(&path);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source_port, "error");
        assert_eq!(out[0].payload["timeout"], true);
    }

    #[tokio::test]
    async fn validate_rejects_relative_socket_and_unknown_method() {
        let mut node = test_node("relative.sock", "/echo", 100);
        assert!(node.validate().await.is_err());

        node.socket_path = "/tmp/z8-test.sock".to_string();
        node.method = "TRACE".to_string();
        assert!(node.validate().await.is_err());

        node.method = "POST".to_string();
        node.max_response_bytes = 0;
        assert!(node.validate().await.is_err());
    }
}
