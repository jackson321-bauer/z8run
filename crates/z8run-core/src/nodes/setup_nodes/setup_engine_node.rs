//! setup-engine: duenner Shim. Die WAHRHEIT liegt in `setup_kern`
//! (dasselbe Modul importiert `bins/z8-setup`) — hier nur Verkabelung.

use serde_json::Value;

use super::setup_io::{body, S3Cfg};
use super::setup_kern;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;

pub struct SetupEngineNode {
    name: String,
    s3_config: String,
}

#[async_trait::async_trait]
impl NodeExecutor for SetupEngineNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let cfg = match S3Cfg::aus_datei(&self.s3_config) {
            Ok(c) => c,
            Err(e) => return Ok(super::setup_io::fehler(&msg, format!("setup-engine: {e}"))),
        };
        let cfg = match cfg.mit_override(req.get("s3").unwrap_or(req)) {
            Ok(c) => c,
            Err(e) => return Ok(super::setup_io::fehler(&msg, format!("setup-engine: {e}"))),
        };
        match setup_kern::init_welt(&cfg, req).await {
            Ok(w) => Ok(vec![msg.derive(msg.source_node, "output", w)]),
            Err(e) => Ok(super::setup_io::fehler(&msg, format!("setup-engine: {e}"))),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.s3_config, "setup-engine braucht s3Config")?;
        Ok(())
    }

    fn node_type(&self) -> &str {
        "setup-engine"
    }
}

node_factory!(SetupEngineNodeFactory, SetupEngineNode, "setup-engine", {
    name: "setup-engine".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
});
