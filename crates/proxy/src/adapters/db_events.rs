//! Event-/Cluster-Uebersetzung der DB-Message-Naht.

use proxy_kern::ProxyError;
use serde_json::Value;
use z8run_core::dbnode::DbNodeEvent;

pub(super) fn event_value(ev: DbNodeEvent) -> Result<Value, ProxyError> {
    let out = match ev {
        DbNodeEvent::Rows { outcome, .. } => serde_json::to_value(outcome),
        DbNodeEvent::WriteOk { outcome, .. } => serde_json::to_value(outcome),
        DbNodeEvent::Ok { status, op, db_id } => Ok(serde_json::json!({
            "ok": true, "op": op, "db_id": db_id, "status": status,
        })),
        DbNodeEvent::Status { dbs } => serde_json::to_value(dbs),
        DbNodeEvent::Schema { schema } => serde_json::to_value(schema),
        DbNodeEvent::WalProgress { progress } => serde_json::to_value(progress),
        DbNodeEvent::LinefsOk { ergebnis, .. } => Ok(ergebnis),
        DbNodeEvent::BlobOk { ergebnis, .. } => Ok(ergebnis),
        DbNodeEvent::Error {
            code,
            message,
            db_id,
        } => {
            return Err(ProxyError::Db(format!("{code} ({db_id}): {message}")));
        }
    };
    out.map_err(|e| ProxyError::Db(format!("Event serialisieren: {e}")))
}

pub(super) fn cluster(v: Value) -> Result<z8run_core::dbnode::ClusterConfig, ProxyError> {
    serde_json::from_value(v).map_err(|e| ProxyError::Db(format!("Cluster-Config: {e}")))
}

