//! Kein DB-Kanal konfiguriert (reine Kern-/HTTP-Tests).

use async_trait::async_trait;
use proxy_kern::{DbPort, ProxyError};
use serde_json::Value;

/// Kein DB-Kanal konfiguriert (z.B. in reinen Kern-/HTTP-Tests).
pub struct NoDb;

#[async_trait]
impl DbPort for NoDb {
    async fn open_db(&self, _: &str, _: &str, _: Value) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn close_db(&self, _: &str) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn reserve(&self, _: &str, _: &str) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn release(&self, _: &str, _: &str) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn query(
        &self,
        _: &str,
        _: &str,
        _: Vec<Value>,
        _: bool,
    ) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn write(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Vec<Value>,
    ) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn status(&self, _: Option<&str>) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
    async fn schema(&self, _: &str) -> Result<Value, ProxyError> {
        Err(ProxyError::Db("DB-Kanal nicht konfiguriert".into()))
    }
}

