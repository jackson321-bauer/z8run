//! Scoped DB-Operationen: jede Anfrage prueft Session-Token UND DB-Scope.
//! Schreibvorgaenge tragen Meta (reservation_change) + Trace-Span.

use proxy_kern::{meta::EventKind, Direction, ProxyError, SessionInfo, SpanStatus};
use serde_json::Value;

use crate::service::ProxyService;

impl ProxyService {
    /// Token + Scope in einem Schritt. Fremde db_id => NOT_IN_SCOPE (403).
    pub fn require_scope(&self, token: &str, db_id: &str) -> Result<SessionInfo, ProxyError> {
        let info = self.authenticate(token)?;
        if !info.dbs.iter().any(|d| d == db_id) {
            return Err(ProxyError::NotInScope);
        }
        Ok(info)
    }

    pub async fn db_query(
        &self,
        token: &str,
        db_id: &str,
        sql: &str,
        params: Vec<Value>,
        readonly: bool,
    ) -> Result<Value, ProxyError> {
        self.require_scope(token, db_id)?;
        self.db.query(db_id, sql, params, readonly).await
    }

    /// Schreibzugriff mit Reserve/Release um EINEN Schreibvorgang.
    pub async fn db_write(
        &self,
        token: &str,
        db_id: &str,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Value, ProxyError> {
        self.db_write_traced(token, db_id, sql, params, None).await
    }

    /// Wie `db_write`, schreibt Meta + DB-Span im durchgereichten Trace.
    pub async fn db_write_traced(
        &self,
        token: &str,
        db_id: &str,
        sql: &str,
        params: Vec<Value>,
        traceparent: Option<&str>,
    ) -> Result<Value, ProxyError> {
        let info = self.require_scope(token, db_id)?;
        let (ctx, _) = self.ensure_trace(traceparent);
        let start = self.now_ms();
        self.db.reserve(db_id, &info.session_id).await?;
        let out = self.db.write(db_id, &info.session_id, sql, params).await;
        let _ = self.db.release(db_id, &info.session_id).await;
        let ok = out.is_ok();
        self.record_meta(
            "user",
            EventKind::ReservationChange,
            db_id,
            &ctx.trace_id,
            &info.session_id,
            if ok { "ok" } else { "fail" },
            "db_write",
        )
        .await;
        let mut span = proxy_kern::otel::child_span(
            &ctx, &crate::adapters::OsRandom, "db.write", Direction::Internal, start,
        );
        span.end_ms = self.now_ms();
        span.engine_id = "dbnode".into();
        let mut attrs = serde_json::json!({"db_id": db_id});
        if let Ok(v) = &out {
            if let Some(wal) = v.get("wal_nr") {
                attrs["wal_nr"] = wal.clone();
            }
        } else if let Err(e) = &out {
            span.status = SpanStatus::Error;
            attrs["error"] = Value::from(e.code());
        }
        span.attrs = attrs;
        self.write_span(span).await;
        out
    }

    pub async fn db_status(
        &self,
        token: &str,
        db_id: Option<&str>,
    ) -> Result<Value, ProxyError> {
        if let Some(db) = db_id {
            self.require_scope(token, db)?;
        } else {
            self.authenticate(token)?;
        }
        self.db.status(db_id).await
    }

    pub async fn db_schema(&self, token: &str, db_id: &str) -> Result<Value, ProxyError> {
        self.require_scope(token, db_id)?;
        self.db.schema(db_id).await
    }

    pub fn db_scope(&self, token: &str) -> Result<Vec<String>, ProxyError> {
        Ok(self.authenticate(token)?.dbs)
    }
}
