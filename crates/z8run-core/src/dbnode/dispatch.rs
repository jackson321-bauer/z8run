//! Command-Dispatch des DB-NODE (Kanal-Frontend -> Engine-API).

use crate::dbnode::msg::{DbNodeCommand, DbNodeEvent};
use crate::dbnode::types::DbError;
use crate::dbnode::DbNode;

impl DbNode {
    /// Verarbeitet einen Command zu Events (Kanal-Frontend).
    pub async fn execute(&self, cmd: DbNodeCommand) -> Vec<DbNodeEvent> {
        match cmd {
            DbNodeCommand::OpenDb {
                db_id,
                master_key_b64,
                cluster,
            } => {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD.decode(master_key_b64);
                match decoded {
                    Ok(master) => match self.open_db(&db_id, &master, cluster).await {
                        Ok(status) => vec![DbNodeEvent::Ok {
                            op: "open".into(),
                            db_id,
                            status: Some(status),
                        }],
                        Err(e) => vec![err(db_id, e)],
                    },
                    Err(e) => vec![DbNodeEvent::Error {
                        db_id,
                        code: "KEY".into(),
                        message: format!("master_key_b64: {e}"),
                    }],
                }
            }
            DbNodeCommand::CloseDb { db_id } => match self.close_db(&db_id) {
                Ok(()) => vec![DbNodeEvent::Ok {
                    op: "close".into(),
                    db_id,
                    status: None,
                }],
                Err(e) => vec![err(db_id, e)],
            },
            DbNodeCommand::Reserve { db_id, session_id } => {
                self.event(self.reserve(&db_id, &session_id), "reserve", db_id)
            }
            DbNodeCommand::Release { db_id, session_id } => {
                self.event(self.release(&db_id, &session_id), "release", db_id)
            }
            DbNodeCommand::Write {
                db_id,
                session_id,
                sql,
                params,
            } => match self.write(&db_id, &session_id, &sql, params).await {
                Ok(outcome) => vec![DbNodeEvent::WriteOk { db_id, outcome }],
                Err(e) => vec![err(db_id, e)],
            },
            DbNodeCommand::Query {
                db_id,
                sql,
                params,
                readonly,
            } => {
                if !readonly {
                    return vec![DbNodeEvent::Error {
                        db_id,
                        code: "READONLY".into(),
                        message: "Query ist readonly; Schreiben läuft über Write".into(),
                    }];
                }
                match self.query(&db_id, &sql, &params) {
                    Ok(outcome) => vec![DbNodeEvent::Rows { db_id, outcome }],
                    Err(e) => vec![err(db_id, e)],
                }
            }
            DbNodeCommand::WalSync { db_id } => match self.wal_sync(&db_id).await {
                Ok(progress) => vec![DbNodeEvent::WalProgress { progress }],
                Err(e) => vec![err(db_id, e)],
            },
            DbNodeCommand::Status { db_id } => match self.status(db_id.as_deref()) {
                Ok(dbs) => vec![DbNodeEvent::Status { dbs }],
                Err(e) => vec![err(db_id.unwrap_or_default(), e)],
            },
            DbNodeCommand::Schema { db_id } => match self.schema(&db_id) {
                Ok(schema) => vec![DbNodeEvent::Schema { schema }],
                Err(e) => vec![err(db_id, e)],
            },
            DbNodeCommand::Linefs(req) => {
                let db_id = req.db_id.clone();
                let op = req.aktion.op().to_string();
                match self.linefs(req).await {
                    Ok(ergebnis) => vec![DbNodeEvent::LinefsOk { db_id, op, ergebnis }],
                    Err(e) => vec![err(db_id, e)],
                }
            }
        }
    }

    fn event(
        &self,
        r: crate::dbnode::types::DbResult<()>,
        op: &str,
        db_id: String,
    ) -> Vec<DbNodeEvent> {
        match r {
            Ok(()) => vec![DbNodeEvent::Ok {
                op: op.into(),
                db_id: db_id.clone(),
                status: self.status(Some(&db_id)).ok().and_then(|v| v.into_iter().next()),
            }],
            Err(e) => vec![err(db_id, e)],
        }
    }
}

fn err(db_id: String, e: DbError) -> DbNodeEvent {
    DbNodeEvent::Error {
        db_id,
        code: e.code,
        message: e.message,
    }
}

