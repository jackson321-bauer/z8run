//! `kv-stream`: duenner Canvas-Node fuer das Kanal-Modell (G1). Spricht
//! den Proxy-Admin-UDS; keine Stream-Logik hier (open/subscribe/claim/push).

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::kv_proxy_node::{at, uds_call};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

pub struct KvStreamNode {
    name: String,
    admin_socket: String,
    action: String,
    channel: String,
    identity: String,
    limit: usize,
}

impl KvStreamNode {
    fn payload_bytes(&self, payload: &Value) -> Vec<u8> {
        if let Some(b64) = at(payload, "bytes_b64").as_str() {
            if let Ok(b) = B64.decode(b64) {
                return b;
            }
        }
        match payload.get("data") {
            Some(Value::String(s)) => s.as_bytes().to_vec(),
            Some(v) if !v.is_null() => serde_json::to_vec(v).unwrap_or_default(),
            _ => payload.to_string().into_bytes(),
        }
    }
}

#[async_trait::async_trait]
impl NodeExecutor for KvStreamNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let channel = if self.channel.is_empty() {
            at(&msg.payload, "channel").as_str().unwrap_or("").to_string()
        } else {
            self.channel.clone()
        };
        let identity = if self.identity.is_empty() {
            at(&msg.payload, "identity").as_str().unwrap_or("node").to_string()
        } else {
            self.identity.clone()
        };
        let mut body = json!({
            "action": self.action,
            "channel": channel,
            "identity": identity,
            "limit": self.limit,
        });
        if self.action == "push" {
            body["payload_b64"] = json!(B64.encode(self.payload_bytes(&msg.payload)));
        }
        let token = at(&msg.payload, "proxy_token").as_str().map(str::to_string);
        let result = uds_call(
            &self.admin_socket,
            "POST",
            "/v1/stream/ctl",
            Some(body),
            token.as_deref(),
        )
        .await;
        let (status, value) = match result {
            Ok(v) => v,
            Err(e) => {
                let mut out = msg.payload.clone();
                if let Some(o) = out.as_object_mut() {
                    o.insert("stream_error".into(), json!(e));
                }
                return Ok(vec![msg.derive(msg.source_node, "error", out)]);
            }
        };
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("stream_status".into(), json!(status));
            o.insert("stream_result".into(), value);
        }
        let port = if status == 200 { "output" } else { "error" };
        Ok(vec![msg.derive(msg.source_node, port, out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "adminSocket" => admin_socket: str,
            "action" => action: str,
            "channel" => channel: str,
            "identity" => identity: str,
        );
        if let Some(v) = config.get("limit").and_then(Value::as_u64) {
            self.limit = v as usize;
        }
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        if self.admin_socket.is_empty() {
            return Err(crate::error::Z8Error::Internal(
                "kv-stream braucht adminSocket".into(),
            ));
        }
        let ok = ["open", "subscribe", "claim", "release", "push"];
        if !ok.contains(&self.action.as_str()) {
            return Err(crate::error::Z8Error::Internal(format!(
                "kv-stream action ungueltig: {}",
                self.action
            )));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv-stream"
    }
}

node_factory!(KvStreamNodeFactory, KvStreamNode, "kv-stream", {
    name: String::new(),
    admin_socket: "/data/z8run/kv-proxy-admin.sock".to_string(),
    action: "claim".to_string(),
    channel: String::new(),
    identity: String::new(),
    limit: 64usize,
});
