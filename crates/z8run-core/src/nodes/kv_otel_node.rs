//! `kv-otel`: duenner Canvas-Node fuer die Logging-Welten. Fragt die
//! Proxy-Logging-Endpunkte (trace_full/span_query/meta_query/export_otel)
//! ueber den Admin-UDS; keine eigene Logging-Logik hier.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::kv_proxy_node::{at, uds_call};
use serde_json::{json, Value};

pub struct KvOtelNode {
    name: String,
    admin_socket: String,
    action: String,
    trace_id: String,
    limit: usize,
}

impl KvOtelNode {
    fn trace_of(&self, payload: &Value) -> String {
        if !self.trace_id.is_empty() {
            return self.trace_id.clone();
        }
        // Dynamisch aus dem vorherigen kv-proxy-Node (Login liefert trace_id).
        for p in ["proxy_result.trace_id", "trace_id"] {
            if let Some(t) = at(payload, p).as_str() {
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
        String::new()
    }

    fn route(&self, t: &str) -> (String, String) {
        match self.action.as_str() {
            "trace_full" => ("GET".into(), format!("/v1/trace/full?trace_id={t}")),
            "span_query" => ("GET".into(), format!("/v1/spans?trace_id={t}")),
            "meta_query" => ("POST".into(), "/v1/meta/query".into()),
            "export_otel" => ("POST".into(), "/v1/export/otel".into()),
            _ => ("GET".into(), format!("/v1/trace/full?trace_id={t}")),
        }
    }

    fn body(&self, t: &str) -> Option<Value> {
        match self.action.as_str() {
            "meta_query" => Some(json!({"trace_id": t, "limit": self.limit})),
            "export_otel" => Some(json!({"trace_id": t})),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl NodeExecutor for KvOtelNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let trace_id = self.trace_of(&msg.payload);
        let (method, uri) = self.route(&trace_id);
        let token = at(&msg.payload, "proxy_token")
            .as_str()
            .map(|s| s.to_string());
        let result = uds_call(
            &self.admin_socket,
            &method,
            &uri,
            self.body(&trace_id),
            token.as_deref(),
        )
        .await;
        let (status, value) = match result {
            Ok(v) => v,
            Err(e) => {
                let mut out = msg.payload.clone();
                if let Some(o) = out.as_object_mut() {
                    o.insert("otel_error".into(), json!(e));
                }
                return Ok(vec![msg.derive(msg.source_node, "error", out)]);
            }
        };
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("otel_status".into(), json!(status));
            o.insert("otel_result".into(), value);
        }
        let port = if status == 200 { "output" } else { "error" };
        Ok(vec![msg.derive(msg.source_node, port, out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "adminSocket" => admin_socket: str,
            "action" => action: str,
            "traceId" => trace_id: str,
        );
        if let Some(v) = config.get("limit").and_then(|v| v.as_u64()) {
            self.limit = v as usize;
        }
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        if self.admin_socket.is_empty() {
            return Err(crate::error::Z8Error::Internal(
                "kv-otel braucht adminSocket".into(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv-otel"
    }
}

node_factory!(KvOtelNodeFactory, KvOtelNode, "kv-otel", {
    name: String::new(),
    admin_socket: "/data/z8run/kv-proxy-admin.sock".to_string(),
    action: "trace_full".to_string(),
    trace_id: String::new(),
    limit: 1000,
});
