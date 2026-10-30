//! Dünne Z8-Nodes der Zeilen-Welt: linefs-open/read/write/close.
//! Engine dahinter (LineFS-Matrix), Kategorie files.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at, at_str, engine, err, ok};
use serde_json::Value;
use crate::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};

fn db_id(cfg: &str, payload: &Value) -> String {
    if cfg.is_empty() { at_str(payload, "db_id", "default") } else { cfg.to_string() }
}

fn session(cfg: &str, payload: &Value) -> String {
    at_str(payload, cfg, "session")
}

async fn dispatch(
    msg: &FlowMessage, db: String, sess: String, auto: bool, aktion: LinefsAktion,
) -> Z8Result<Vec<FlowMessage>> {
    let node = engine();
    if auto {
        if let Err(e) = node.reserve(&db, &sess) {
            return Ok(err(msg, &e.code, &e.message));
        }
    }
    let r = node.linefs(LinefsRequest {
        db_id: db.clone(), session_id: sess.clone(), aktion,
    }).await;
    if auto {
        let _ = node.release(&db, &sess);
    }
    match r {
        Ok(v) => Ok(ok(msg, v)),
        Err(e) => Ok(err(msg, &e.code, &e.message)),
    }
}

pub struct LinefsOpenNode {
    name: String,
    db_id: String,
    pfad: String,
    pfad_path: String,
    session_path: String,
    auto_reserve: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for LinefsOpenNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let sess = session(&self.session_path, &msg.payload);
        let pfad = if self.pfad.is_empty() {
            at_str(&msg.payload, &self.pfad_path, "")
        } else {
            self.pfad.clone()
        };
        dispatch(&msg, db, sess, self.auto_reserve, LinefsAktion::LinefsOeffnen { pfad }).await
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "pfad" => pfad: str, "pfadPath" => pfad_path: str,
            "sessionPath" => session_path: str, "autoReserve" => auto_reserve: bool);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "linefs-open" }
}

node_factory!(LinefsOpenNodeFactory, LinefsOpenNode, "linefs-open", {
    name: String::new(), db_id: String::new(), pfad: String::new(),
    pfad_path: "req.body.pfad".to_string(),
    session_path: "session_id".to_string(), auto_reserve: true
});

pub struct LinefsReadNode {
    name: String,
    db_id: String,
    pfad: String,
    session_path: String,
    von_path: String,
    bis_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for LinefsReadNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let sess = session(&self.session_path, &msg.payload);
        let pfad = if self.pfad.is_empty() { at_str(&msg.payload, "pfad", "") } else { self.pfad.clone() };
        let von = at(&msg.payload, &self.von_path).and_then(|v| v.as_i64());
        let bis = at(&msg.payload, &self.bis_path).and_then(|v| v.as_i64());
        dispatch(&msg, db, sess, false, LinefsAktion::LinefsLesen { pfad, von, bis }).await
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "pfad" => pfad: str, "sessionPath" => session_path: str,
            "vonPath" => von_path: str, "bisPath" => bis_path: str);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "linefs-read" }
}

node_factory!(LinefsReadNodeFactory, LinefsReadNode, "linefs-read", {
    name: String::new(), db_id: String::new(), pfad: String::new(),
    session_path: "session_id".to_string(),
    von_path: "von".to_string(), bis_path: "bis".to_string()
});

pub struct LinefsWriteNode {
    name: String,
    db_id: String,
    session_path: String,
    modus: String,
    nr_path: String,
    inhalt_path: String,
    auto_reserve: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for LinefsWriteNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let sess = session(&self.session_path, &msg.payload);
        let nr = at(&msg.payload, &self.nr_path).and_then(|v| v.as_i64()).unwrap_or(1);
        let inhalt = at_str(&msg.payload, &self.inhalt_path, "");
        let aktion = match self.modus.as_str() {
            "einfuegen" => LinefsAktion::LinefsEinfuegen { nr, inhalt },
            "loeschen" => LinefsAktion::LinefsZeileLoeschen { nr },
            _ => LinefsAktion::LinefsZeileSetzen { nr, inhalt },
        };
        dispatch(&msg, db, sess, self.auto_reserve, aktion).await
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "sessionPath" => session_path: str, "modus" => modus: str,
            "nrPath" => nr_path: str, "inhaltPath" => inhalt_path: str,
            "autoReserve" => auto_reserve: bool);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "linefs-write" }
}

node_factory!(LinefsWriteNodeFactory, LinefsWriteNode, "linefs-write", {
    name: String::new(), db_id: String::new(),
    session_path: "session_id".to_string(), modus: "setzen".to_string(),
    nr_path: "nr".to_string(), inhalt_path: "inhalt".to_string(), auto_reserve: true
});

pub struct LinefsCloseNode {
    name: String,
    db_id: String,
    session_path: String,
    auto_reserve: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for LinefsCloseNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = db_id(&self.db_id, &msg.payload);
        let sess = session(&self.session_path, &msg.payload);
        dispatch(&msg, db, sess, self.auto_reserve, LinefsAktion::LinefsSchliessen).await
    }
    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str,
            "sessionPath" => session_path: str, "autoReserve" => auto_reserve: bool);
        Ok(())
    }
    async fn validate(&self) -> Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "linefs-close" }
}

node_factory!(LinefsCloseNodeFactory, LinefsCloseNode, "linefs-close", {
    name: String::new(), db_id: String::new(),
    session_path: "session_id".to_string(), auto_reserve: true
});
