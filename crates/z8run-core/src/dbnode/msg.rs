//! Natives Nachrichten-Interface (kein HTTP): Command/Event, serde-fähig,
//! über einen lokalen tokio-mpsc-Kanal bewiesen. Der spätere Proxy spricht
//! genau dieses Protokoll.

use crate::dbnode::types::{
    ClusterConfig, DbStatus, QueryOutcome, SchemaInfo, WalProgress, WriteOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbNodeCommand {
    OpenDb {
        db_id: String,
        /// Masterkey von außen (Login/Proxy-Scope), nur im Speicher.
        master_key_b64: String,
        cluster: ClusterConfig,
    },
    CloseDb {
        db_id: String,
    },
    Reserve {
        db_id: String,
        session_id: String,
    },
    Release {
        db_id: String,
        session_id: String,
    },
    Write {
        db_id: String,
        session_id: String,
        sql: String,
        params: Vec<Value>,
    },
    Query {
        db_id: String,
        sql: String,
        params: Vec<Value>,
        readonly: bool,
    },
    WalSync {
        db_id: String,
    },
    Status {
        db_id: Option<String>,
    },
    Schema {
        db_id: String,
    },
    /// Vollstaendige LineFS-Befehlsmatrix (Zeilen + Ordner + Binaer).
    Linefs(crate::dbnode::linefs_rows::LinefsRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbNodeEvent {
    Ok {
        op: String,
        db_id: String,
        status: Option<DbStatus>,
    },
    WriteOk {
        db_id: String,
        outcome: WriteOutcome,
    },
    Rows {
        db_id: String,
        outcome: QueryOutcome,
    },
    WalProgress {
        progress: WalProgress,
    },
    Status {
        dbs: Vec<DbStatus>,
    },
    Schema {
        schema: SchemaInfo,
    },
    LinefsOk {
        db_id: String,
        op: String,
        ergebnis: Value,
    },
    Error {
        db_id: String,
        code: String,
        message: String,
    },
}

/// Kanalserver: verarbeitet Commands sequenziell, emittiert Events.
pub async fn serve(
    node: std::sync::Arc<crate::dbnode::DbNode>,
    mut rx: mpsc::Receiver<DbNodeCommand>,
    tx: mpsc::Sender<DbNodeEvent>,
) {
    while let Some(cmd) = rx.recv().await {
        for ev in node.execute(cmd).await {
            if tx.send(ev).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_und_event_sind_json_serialisierbar() {
        let cmd = DbNodeCommand::Query {
            db_id: "d1".into(),
            sql: "SELECT 1".into(),
            params: vec![],
            readonly: true,
        };
        let s = serde_json::to_string(&cmd).unwrap();
        assert!(s.contains("Query"));
        let back: DbNodeCommand = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, DbNodeCommand::Query { .. }));

        let ev = DbNodeEvent::Error {
            db_id: "d1".into(),
            code: "X".into(),
            message: "y".into(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"Error\""));
    }
}
