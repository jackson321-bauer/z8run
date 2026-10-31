//! Scoped DB-Operationen: jede Anfrage prueft Session-Token UND DB-Scope.

use proxy_kern::{ProxyError, SessionInfo};
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
        let info = self.require_scope(token, db_id)?;
        self.db.reserve(db_id, &info.session_id).await?;
        let out = self.db.write(db_id, &info.session_id, sql, params).await;
        let _ = self.db.release(db_id, &info.session_id).await;
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
