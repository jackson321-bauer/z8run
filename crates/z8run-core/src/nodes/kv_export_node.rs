//! `kv-export`: duenner Canvas-Node fuer den Gesamt-Export (G12). Reicht
//! Selektion an `/v1/export/all` weiter; keine Export-Logik hier.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::kv_proxy_node::{at, uds_call};
use serde_json::{json, Value};

pub struct KvExportNode {
    name: String,
    admin_socket: String,
    password: String,
    worlds: String,
    db_id: String,
    sessions: String,
    from_ms: u64,
    to_ms: u64,
}

fn list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

#[async_trait::async_trait]
impl NodeExecutor for KvExportNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let password = if self.password.is_empty() {
            at(&msg.payload, "export_password").as_str().unwrap_or("").to_string()
        } else {
            self.password.clone()
        };
        let body = json!({
            "worlds": list(&self.worlds),
            "db_id": if self.db_id.is_empty() { Value::Null } else { json!(self.db_id) },
            "sessions": list(&self.sessions),
            "from_ms": if self.from_ms == 0 { Value::Null } else { json!(self.from_ms) },
            "to_ms": if self.to_ms == 0 { Value::Null } else { json!(self.to_ms) },
            "password": password,
        });
        let token = at(&msg.payload, "proxy_token").as_str().map(str::to_string);
        let result = uds_call(
            &self.admin_socket,
            "POST",
            "/v1/export/all",
            Some(body),
            token.as_deref(),
        )
        .await;
        let (status, value) = match result {
            Ok(v) => v,
            Err(e) => {
                let mut out = msg.payload.clone();
                if let Some(o) = out.as_object_mut() {
                    o.insert("export_error".into(), json!(e));
                }
                return Ok(vec![msg.derive(msg.source_node, "error", out)]);
            }
        };
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("export_status".into(), json!(status));
            o.insert("export_manifest".into(), value.get("manifest").cloned().unwrap_or(Value::Null));
            o.insert("export_container_b64".into(), value.get("container_b64").cloned().unwrap_or(Value::Null));
        }
        let port = if status == 200 { "output" } else { "error" };
        Ok(vec![msg.derive(msg.source_node, port, out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "adminSocket" => admin_socket: str,
            "password" => password: str,
            "worlds" => worlds: str,
            "dbId" => db_id: str,
            "sessions" => sessions: str,
        );
        if let Some(v) = config.get("fromMs").and_then(Value::as_u64) {
            self.from_ms = v;
        }
        if let Some(v) = config.get("toMs").and_then(Value::as_u64) {
            self.to_ms = v;
        }
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        if self.admin_socket.is_empty() {
            return Err(crate::error::Z8Error::Internal(
                "kv-export braucht adminSocket".into(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "kv-export"
    }
}

node_factory!(KvExportNodeFactory, KvExportNode, "kv-export", {
    name: String::new(),
    admin_socket: "/data/z8run/kv-proxy-admin.sock".to_string(),
    password: String::new(),
    worlds: String::new(),
    db_id: String::new(),
    sessions: String::new(),
    from_ms: 0u64,
    to_ms: 0u64,
});
