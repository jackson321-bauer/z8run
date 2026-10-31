//! Meta-DB-Adapter: schreibt Ereignisse in die Meta-Welt (User-Meta global
//! + Cluster-Meta). WORM auf DB-Ebene: DELETE/UPDATE werden per Trigger
//! abgelehnt, nicht nur per Konvention.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use proxy_kern::meta::{detail_haelt_inhalt_nicht, sql_ist_meta_worm_konform, MetaEvent};
use proxy_kern::{DbPort, ProxyError};
use serde_json::Value;

const CREATE: &str = "CREATE TABLE IF NOT EXISTS meta_events (\
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, \
 object_ref TEXT NOT NULL, trace_id TEXT NOT NULL, session TEXT NOT NULL, \
 status TEXT NOT NULL, detail TEXT NOT NULL, ts_ms INTEGER NOT NULL)";
const INDEX_TRACE: &str =
    "CREATE INDEX IF NOT EXISTS idx_meta_trace ON meta_events(trace_id)";
const INDEX_ACTION: &str =
    "CREATE INDEX IF NOT EXISTS idx_meta_action ON meta_events(action)";
const INSERT: &str = "INSERT INTO meta_events \
 (actor, action, object_ref, trace_id, session, status, detail, ts_ms) \
 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
const SELECT: &str = "SELECT actor, action, object_ref, trace_id, session, status, detail, ts_ms \
 FROM meta_events";

pub struct MetaStore {
    db: Arc<dyn DbPort>,
    dbs: Vec<String>,
    session_id: String,
    schema_ready: AtomicBool,
}

impl MetaStore {
    pub fn new(db: Arc<dyn DbPort>, dbs: Vec<String>) -> Self {
        Self {
            db,
            dbs,
            session_id: "meta-writer".into(),
            schema_ready: AtomicBool::new(false),
        }
    }

    pub fn db_ids(&self) -> &[String] {
        &self.dbs
    }

    async fn exec_on(&self, db_id: &str, sql: &str, params: Vec<Value>) -> Result<Value, ProxyError> {
        if !sql_ist_meta_worm_konform(sql) {
            return Err(ProxyError::BadRequest("Meta-WORM: Schreibart abgelehnt".into()));
        }
        self.db.reserve(db_id, &self.session_id).await?;
        let out = self
            .db
            .write(db_id, &self.session_id, sql, params)
            .await;
        let _ = self.db.release(db_id, &self.session_id).await;
        out
    }

    async fn ensure_schema(&self) -> Result<(), ProxyError> {
        if self.schema_ready.load(Ordering::Relaxed) {
            return Ok(());
        }
        for db_id in &self.dbs {
            self.exec_on(db_id, CREATE, vec![]).await?;
            self.exec_on(db_id, INDEX_TRACE, vec![]).await?;
            self.exec_on(db_id, INDEX_ACTION, vec![]).await?;
            // WORM-Trigger (DB-Ebene, unumgehbar fuer dieses Handle).
            self.exec_on(
                db_id,
                "CREATE TRIGGER IF NOT EXISTS meta_events_no_delete BEFORE DELETE ON meta_events \
                 BEGIN SELECT RAISE(ABORT, 'WORM'); END",
                vec![],
            )
            .await?;
            self.exec_on(
                db_id,
                "CREATE TRIGGER IF NOT EXISTS meta_events_no_update BEFORE UPDATE ON meta_events \
                 BEGIN SELECT RAISE(ABORT, 'WORM'); END",
                vec![],
            )
            .await?;
        }
        self.schema_ready.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Jede Aktion erzeugt mind. einen Meta-Eintrag (Decke).
    pub async fn record(&self, event: &MetaEvent) -> Result<(), ProxyError> {
        event.validate()?;
        self.ensure_schema().await?;
        let params = vec![
            Value::from(event.actor.clone()),
            Value::from(event.action.clone()),
            Value::from(event.object_ref.clone()),
            Value::from(event.trace_id.clone()),
            Value::from(event.session.clone()),
            Value::from(event.status.clone()),
            Value::from(event.detail.clone()),
            Value::from(event.ts_ms as i64),
        ];
        for db_id in &self.dbs {
            self.exec_on(db_id, INSERT, params.clone()).await?;
        }
        Ok(())
    }

    /// Negativregel: Inhalt im detail-Feld = abgelehnt.
    pub async fn record_guarded(
        &self,
        event: &MetaEvent,
        content: &str,
    ) -> Result<(), ProxyError> {
        if !detail_haelt_inhalt_nicht(&event.detail, content) {
            return Err(ProxyError::BadRequest(
                "Meta-detail enthaelt Inhalt".into(),
            ));
        }
        self.record(event).await
    }

    pub async fn query(
        &self,
        trace_id: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MetaEvent>, ProxyError> {
        let mut sql = format!("{SELECT} WHERE 1=1");
        let mut params: Vec<Value> = Vec::new();
        if let Some(t) = trace_id {
            params.push(Value::from(t));
            sql.push_str(&format!(" AND trace_id = ?{}", params.len()));
        }
        if let Some(a) = action {
            params.push(Value::from(a));
            sql.push_str(&format!(" AND action = ?{}", params.len()));
        }
        sql.push_str(&format!(" ORDER BY id LIMIT {}", limit.max(1)));
        let Some(db_id) = self.dbs.first() else {
            return Ok(Vec::new());
        };
        let out = self.db.query(db_id, &sql, params, true).await?;
        rows_to_events(&out)
    }

    /// WORM-Beweis: roher DELETE (umgeht den Kernel-Guard absichtlich).
    pub async fn delete_all_raw(&self) -> Result<(), ProxyError> {
        let Some(db_id) = self.dbs.first() else {
            return Ok(());
        };
        self.db.reserve(db_id, &self.session_id).await?;
        let out = self
            .db
            .write(db_id, &self.session_id, "DELETE FROM meta_events", vec![])
            .await;
        let _ = self.db.release(db_id, &self.session_id).await;
        out.map(|_| ())
    }
}

fn cell(row: &Value, i: usize) -> Value {
    row.get(i).cloned().unwrap_or(Value::Null)
}

fn text(row: &Value, i: usize) -> String {
    cell(row, i).as_str().unwrap_or("").to_string()
}

fn rows_to_events(out: &Value) -> Result<Vec<MetaEvent>, ProxyError> {
    let rows = out
        .get("rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(rows
        .iter()
        .map(|r| MetaEvent {
            actor: text(r, 0),
            action: text(r, 1),
            object_ref: text(r, 2),
            trace_id: text(r, 3),
            session: text(r, 4),
            status: text(r, 5),
            detail: text(r, 6),
            ts_ms: cell(r, 7).as_u64().unwrap_or(0),
        })
        .collect())
}
