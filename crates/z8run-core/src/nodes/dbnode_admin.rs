//! `db-schema` (Canvas-Felder), `db-status` (Badge) und `db-sync` (WAL).

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at_str, engine, err, ok};
use serde_json::{json, Value};

pub struct DbSchemaNode {
    name: String,
    db_id: String,
}

#[async_trait::async_trait]
impl NodeExecutor for DbSchemaNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        match engine().schema(&db) {
            Ok(schema) => {
                let tabellen: Vec<Value> = schema
                    .tables
                    .iter()
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "spalten": t.columns.iter()
                                .map(|c| json!({"name": c.name, "typ": c.typ}))
                                .collect::<Vec<_>>(),
                            "zeilen": t.rows,
                            "wal_stand": t.wal_stand,
                            "reserviert_von": t.reserved_by,
                        })
                    })
                    .collect();
                Ok(ok(
                    &msg,
                    json!({"status": 200, "db": db, "db_id": schema.db_id,
                           "tables": schema.tables, "tabellen": tabellen}),
                ))
            }
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "db-schema"
    }
}

node_factory!(DbSchemaNodeFactory, DbSchemaNode, "db-schema", {
    name: String::new(),
    db_id: String::new()
});

pub struct DbStatusNode {
    name: String,
    db_id: String,
}

#[async_trait::async_trait]
impl NodeExecutor for DbStatusNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "")
        } else {
            self.db_id.clone()
        };
        let filter = if db.is_empty() { None } else { Some(db.as_str()) };
        match engine().status(filter) {
            Ok(dbs) => Ok(ok(&msg, json!({"status": 200, "dbs": dbs}))),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "db-status"
    }
}

node_factory!(DbStatusNodeFactory, DbStatusNode, "db-status", {
    name: String::new(),
    db_id: String::new()
});

pub struct DbSyncNode {
    name: String,
    db_id: String,
}

#[async_trait::async_trait]
impl NodeExecutor for DbSyncNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        match engine().wal_sync(&db).await {
            Ok(p) => Ok(ok(&msg, json!({"status": 200, "progress": p}))),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self, "name" => name: str, "dbId" => db_id: str);
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "db-sync"
    }
}

node_factory!(DbSyncNodeFactory, DbSyncNode, "db-sync", {
    name: String::new(),
    db_id: String::new()
});
