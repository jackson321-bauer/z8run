//! Ports des Kerns. Nativ-Adapter und (spaeter) Browser-Adapter
//! implementieren diese Traits; der Kern selbst macht kein I/O.

use async_trait::async_trait;
use serde_json::Value;

use crate::error::ProxyError;

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait Random: Send + Sync {
    fn fill(&self, buf: &mut [u8]);
}

/// Versions-Bundle lesen (FS, S3, spaeter OPFS).
#[async_trait]
pub trait StoragePort: Send + Sync {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, ProxyError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ProxyError>;
}

/// Ein-Schreiber-Naht zur dbnode-Engine (nativ: UDS-Messages).
#[async_trait]
pub trait DbPort: Send + Sync {
    async fn open_db(
        &self,
        db_id: &str,
        master_key_b64: &str,
        cluster: Value,
    ) -> Result<Value, ProxyError>;
    async fn close_db(&self, db_id: &str) -> Result<Value, ProxyError>;
    async fn reserve(&self, db_id: &str, session_id: &str) -> Result<Value, ProxyError>;
    async fn release(&self, db_id: &str, session_id: &str) -> Result<Value, ProxyError>;
    async fn query(
        &self,
        db_id: &str,
        sql: &str,
        params: Vec<Value>,
        readonly: bool,
    ) -> Result<Value, ProxyError>;
    async fn write(
        &self,
        db_id: &str,
        session_id: &str,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Value, ProxyError>;
    async fn status(&self, db_id: Option<&str>) -> Result<Value, ProxyError>;
    async fn schema(&self, db_id: &str) -> Result<Value, ProxyError>;
}

/// LLM-Port. In PROXY-1 eine Attrappe (Mock); echte Endpoints erst PROXY-2/3.
#[async_trait]
pub trait LlmPort: Send + Sync {
    async fn complete(&self, system: &str, user: &str) -> Result<Value, ProxyError>;
}

/// Quelle fuer die Stream-Durchreichung (z.B. DB-BLOB-Playback).
pub trait ByteSource: Send {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProxyError>;
}

/// Senke fuer die Stream-Durchreichung (z.B. HTTP-chunked/SSE).
pub trait ByteSink: Send {
    fn write_chunk(&mut self, data: &[u8]) -> Result<(), ProxyError>;
    fn finish(&mut self) -> Result<(), ProxyError>;
}
