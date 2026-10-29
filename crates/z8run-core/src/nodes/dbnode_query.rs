//! `db-query` (readonly, parallel) und `db-write` (Reservierungspflicht,
//! optional auto-reserve+release). Dünn: SQL/Params kommen aus Config/Payload.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;
use crate::nodes::dbnode_common::{at_params, at_str, engine, err, ok};
use serde_json::{json, Value};

pub struct DbQueryNode {
    name: String,
    db_id: String,
    sql: String,
    params_path: String,
}

#[async_trait::async_trait]
impl NodeExecutor for DbQueryNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        let sql = if self.sql.is_empty() {
            at_str(&msg.payload, "sql", "")
        } else {
            self.sql.clone()
        };
        let params = at_params(&msg.payload, &self.params_path);
        match engine().query(&db, &sql, &params) {
            Ok(out) => Ok(ok(
                &msg,
                json!({"status": 200, "db": db, "columns": out.columns,
                       "rows": out.rows, "rowsAffected": out.rows_affected}),
            )),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "dbId" => db_id: str,
            "sql" => sql: str,
            "paramsPath" => params_path: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "db-query"
    }
}

node_factory!(DbQueryNodeFactory, DbQueryNode, "db-query", {
    name: String::new(),
    db_id: String::new(),
    sql: String::new(),
    params_path: "params".to_string()
});

pub struct DbWriteNode {
    name: String,
    db_id: String,
    sql: String,
    params_path: String,
    session_path: String,
    auto_reserve: bool,
}

#[async_trait::async_trait]
impl NodeExecutor for DbWriteNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let db = if self.db_id.is_empty() {
            at_str(&msg.payload, "db_id", "default")
        } else {
            self.db_id.clone()
        };
        let sql = if self.sql.is_empty() {
            at_str(&msg.payload, "sql", "")
        } else {
            self.sql.clone()
        };
        let params = at_params(&msg.payload, &self.params_path);
        let session = at_str(&msg.payload, &self.session_path, "proxy-session");
        let node = engine();

        let auto = self.auto_reserve;
        if auto {
            if let Err(e) = node.reserve(&db, &session) {
                return Ok(err(&msg, &e.code, &e.message));
            }
        }
        let result = node.write(&db, &session, &sql, params).await;
        if auto {
            let _ = node.release(&db, &session);
        }
        match result {
            Ok(out) => Ok(ok(
                &msg,
                json!({"status": 200, "db": db,
                       "rowsAffected": out.rows_affected, "walNr": out.wal_nr}),
            )),
            Err(e) => Ok(err(&msg, &e.code, &e.message)),
        }
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "dbId" => db_id: str,
            "sql" => sql: str,
            "paramsPath" => params_path: str,
            "sessionPath" => session_path: str,
            "autoReserve" => auto_reserve: bool,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "db-write"
    }
}

node_factory!(DbWriteNodeFactory, DbWriteNode, "db-write", {
    name: String::new(),
    db_id: String::new(),
    sql: String::new(),
    params_path: "params".to_string(),
    session_path: "session_id".to_string(),
    auto_reserve: false
});
