//! S3-Adapter (kv-store, SigV4) + DummyBackend (Tests/Nahtbeweis).

use crate::dbnode::storage::StorageBackend;
use crate::dbnode::types::{DbError, DbResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// S3-kompatibel über kv-store (kein Provider-SDK, keine CLI).
pub struct S3Backend {
    endpoint: kv_store::s3::S3Endpoint,
    bucket: String,
    prefix: String,
}

impl S3Backend {
    pub fn new(endpoint: kv_store::s3::S3Endpoint, bucket: String, prefix: String) -> Self {
        Self {
            endpoint,
            bucket,
            prefix,
        }
    }
    fn full(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.prefix.trim_end_matches('/'), key)
        }
    }
    fn base(&self) -> String {
        if self.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.prefix.trim_end_matches('/'))
        }
    }
}

#[async_trait]
impl StorageBackend for S3Backend {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>> {
        match self.endpoint.get_object(&self.bucket, &self.full(key)).await {
            Ok(v) => Ok(Some(v)),
            Err(kv_store::s3::S3Error::Http(404, _)) => Ok(None),
            Err(e) => Err(DbError::new("STORAGE", format!("s3 read: {e}"))),
        }
    }

    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()> {
        self.endpoint
            .put_object(&self.bucket, &self.full(key), data.to_vec())
            .await
            .map_err(|e| DbError::new("STORAGE", format!("s3 write: {e}")))
    }

    async fn list(&self, prefix: &str) -> DbResult<Vec<String>> {
        let objs = self
            .endpoint
            .list_objects(&self.bucket, &self.full(prefix))
            .await
            .map_err(|e| DbError::new("STORAGE", format!("s3 list: {e}")))?;
        let base = self.base();
        let mut out: Vec<String> = objs
            .into_iter()
            .map(|o| o.key.strip_prefix(&base).unwrap_or(&o.key).to_string())
            .collect();
        out.sort();
        Ok(out)
    }

    async fn delete(&self, key: &str) -> DbResult<()> {
        self.endpoint
            .delete_object(&self.bucket, &self.full(key))
            .await
            .map_err(|e| DbError::new("STORAGE", format!("s3 delete: {e}")))
    }

    fn kind(&self) -> &'static str {
        "s3"
    }
}

/// In-Memory-Adapter für Unit-Tests + Nahtbeweis (OPFS dockt genauso an).
pub struct DummyBackend {
    map: Mutex<HashMap<String, Vec<u8>>>,
    online: AtomicBool,
}

impl DummyBackend {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            online: AtomicBool::new(true),
        }
    }
    /// Simuliert einen ausgefallenen Storage (S4-Beweis).
    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::SeqCst);
    }
    pub fn keys(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }
}

impl Default for DummyBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for DummyBackend {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>> {
        self.check_online()?;
        Ok(self.map.lock().unwrap().get(key).cloned())
    }
    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()> {
        self.check_online()?;
        self.map.lock().unwrap().insert(key.to_string(), data.to_vec());
        Ok(())
    }
    async fn list(&self, prefix: &str) -> DbResult<Vec<String>> {
        self.check_online()?;
        let mut v: Vec<String> = self
            .map
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        v.sort();
        Ok(v)
    }
    async fn delete(&self, key: &str) -> DbResult<()> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
    fn kind(&self) -> &'static str {
        "dummy"
    }
}

impl DummyBackend {
    fn check_online(&self) -> DbResult<()> {
        if self.online.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(DbError::new(
                "STORAGE_OFFLINE",
                "Storage nicht erreichbar",
            ))
        }
    }
}
