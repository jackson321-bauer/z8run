//! `db-open`: dünner Wrapper um die DB-Engine. Masterkey aus Payload
//! (Login/Proxy-Scope), Cluster-/Adapter-Wahl aus der Node-Config.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at_str, err_without, master_at, ok_without, ClusterSpec};
use serde_json::{json, Value};

pub struct DbOpenNode {
    name: String,
    db_id: String,
    master_key_path: String,
    cluster: ClusterSpec,
}

impl DbOpenNode {
    fn apply_cluster(&mut self, config: &Value) {
        self.cluster = ClusterSpec::from_config(config);
    }
}

#[async_trait::async_trait]
impl NodeExecutor for DbOpenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db_id = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        let master = match master_at(&msg.payload, &self.master_key_path) {
            Ok(m) => m,
            Err(e) => return Ok(err_without(&msg, "KEY", &e, &self.master_key_path)),
        };
        let engine = crate::nodes::dbnode_common::engine();
        match engine
            .open_db(&db_id, &master, self.cluster.to_cluster())
            .await
        {
            Ok(status) => Ok(ok_without(
                &msg,
                json!({"status": 200, "db": db_id, "db_status": status}),
                &self.master_key_path,
            )),
            Err(e) => Ok(err_without(&msg, &e.code, &e.message, &self.master_key_path)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "dbId" => db_id: str,
            "masterKeyPath" => master_key_path: str,
        );
        self.apply_cluster(&config);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        if self.master_key_path.is_empty() {
            return Err(crate::error::Z8Error::Internal(
                "db-open: masterKeyPath fehlt".into(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "db-open"
    }
}

node_factory!(DbOpenNodeFactory, DbOpenNode, "db-open", {
    name: String::new(),
    db_id: String::new(),
    master_key_path: "master_key_b64".to_string(),
    cluster: ClusterSpec::default()
});
