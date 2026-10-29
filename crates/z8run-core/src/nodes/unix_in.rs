//! Unix In node: trigger node for flows published on the local Unix socket.
//!
//! Behaves like `http-in`: the UDS listener in the server dispatches the
//! request to the flow, and this node turns the trigger payload into the
//! standard `{ req: { method, path, headers, query, body } }` shape.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use tracing::info;

pub struct UnixInNode {
    name: String,
    method: String,
    path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for UnixInNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        info!(
            node = %self.name,
            method = %self.method,
            path = %self.path,
            "Unix In trigger"
        );

        let payload = if msg.payload.get("method").is_some() {
            serde_json::json!({ "req": msg.payload })
        } else if msg.payload.get("req").is_some() {
            msg.payload.clone()
        } else {
            serde_json::json!({
                "req": {
                    "method": self.method,
                    "path": self.path,
                    "headers": {},
                    "query": {},
                    "body": msg.payload,
                }
            })
        };

        let out = msg.derive(msg.source_node, "output", payload);
        Ok(vec![out])
    }

    async fn configure(&mut self, config: serde_json::Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "method" => method: str,
            "path" => path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "unix-in"
    }
}

node_factory!(UnixInNodeFactory, UnixInNode, "unix-in", {
    name: String::new(),
    method: "POST".to_string(),
    path: "/".to_string()
});

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_msg(payload: serde_json::Value) -> FlowMessage {
        FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7())
    }

    #[tokio::test]
    async fn wraps_raw_request_into_req_envelope() {
        let node = UnixInNode {
            name: "Unix In".to_string(),
            method: "POST".to_string(),
            path: "/echo".to_string(),
        };

        let out = node
            .process(test_msg(serde_json::json!({
                "method": "POST",
                "path": "/echo",
                "body": {"a": 1}
            })))
            .await
            .unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source_port, "output");
        assert_eq!(out[0].payload["req"]["method"], "POST");
        assert_eq!(out[0].payload["req"]["body"]["a"], 1);
    }

    #[tokio::test]
    async fn passes_existing_req_envelope_through() {
        let node = UnixInNode {
            name: "Unix In".to_string(),
            method: "POST".to_string(),
            path: "/echo".to_string(),
        };

        let original = serde_json::json!({
            "req": {"method": "GET", "path": "/x", "body": null}
        });
        let out = node.process(test_msg(original.clone())).await.unwrap();

        assert_eq!(out[0].payload, original);
    }
}
