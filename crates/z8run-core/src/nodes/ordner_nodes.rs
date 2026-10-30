//! Dünne Z8-Nodes der Ordner-Sicht: linefs-list, ordner-list, ordner-pfad.

use crate::configure_fields;
use crate::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at, at_str, engine, err, ok};
use serde_json::Value;

fn db_id(cfg: &str, payload: &Value) -> String {
    if cfg.is_empty() { at_str(payload, "db_id", "default") } else { cfg.to_string() }
}

async fn listen(msg: &FlowMessage, db: String, eltern_id: i64) -> Z8Result<Vec<FlowMessage>> {
    match engine().linefs(LinefsRequest {
        db_id: db, session_id: "list".into(),
        aktion: LinefsAktion::OrdnerListen { eltern_id },
    }).await {
        Ok(v) => Ok(ok(msg, v)),
        Err(e) => Ok(err(msg, &e.code, &e.message)),
    }
}

pub struct LinefsListNode {
    name: String,
    db_id: String,
    eltern_id: u64,
    eltern_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for LinefsListNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let eltern = at(&msg.payload, &self.eltern_path).and_then(|v| v.as_i64()).unwrap_or(self.eltern_id as i64);
        listen(&msg, db, eltern).await
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "elternId" => eltern_id: u64, "elternIdPath" => eltern_path: str);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "linefs-list" }
}

node_factory!(LinefsListNodeFactory, LinefsListNode, "linefs-list", {
    name: String::new(), db_id: String::new(), eltern_id: 0_u64,
    eltern_path: "eltern_id".to_string()
});

pub struct OrdnerListNode {
    name: String,
    db_id: String,
    eltern_id: u64,
    eltern_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for OrdnerListNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let eltern = at(&msg.payload, &self.eltern_path).and_then(|v| v.as_i64()).unwrap_or(self.eltern_id as i64);
        listen(&msg, db, eltern).await
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "elternId" => eltern_id: u64, "elternIdPath" => eltern_path: str);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "ordner-list" }
}

node_factory!(OrdnerListNodeFactory, OrdnerListNode, "ordner-list", {
    name: String::new(), db_id: String::new(), eltern_id: 0_u64,
    eltern_path: "eltern_id".to_string()
});

pub struct OrdnerPfadNode {
    name: String,
    db_id: String,
    pfad: String,
    pfad_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for OrdnerPfadNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let pfad = if self.pfad.is_empty() {
            at_str(&msg.payload, &self.pfad_path, "")
        } else {
            self.pfad.clone()
        };
        match engine().linefs(LinefsRequest {
            db_id: db, session_id: "pfad".into(),
            aktion: LinefsAktion::OrdnerPfadAufloesen { pfad },
        }).await {
            Ok(v) => Ok(ok(&msg, v)),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "pfad" => pfad: str, "pfadPath" => pfad_path: str);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "ordner-pfad" }
}

node_factory!(OrdnerPfadNodeFactory, OrdnerPfadNode, "ordner-pfad", {
    name: String::new(), db_id: String::new(), pfad: String::new(),
    pfad_path: "pfad".to_string()
});
