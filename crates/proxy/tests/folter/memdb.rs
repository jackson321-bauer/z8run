//! In-Memory-DbPort fuer die Folter: reale Blob-Session-Semantik (begin/
//! append/finish/get) ohne Platte, damit die Aufnahme-Kanäle verlustfrei
//! nachgewiesen werden koennen.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use proxy_kern::{DbPort, ProxyError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Default)]
pub struct MemDb {
    next: Mutex<u64>,
    sessions: Mutex<HashMap<String, Vec<u8>>>,
    frames: Mutex<HashMap<String, u64>>,
    reserved: Mutex<HashSet<String>>,
}

#[async_trait]
impl DbPort for MemDb {
    async fn open_db(&self, _: &str, _: &str, _: Value) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn close_db(&self, _: &str) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn reserve(&self, db: &str, session: &str) -> Result<Value, ProxyError> {
        // Echte Ein-Schreiber-Semantik: je DB nur EINE Reservierung.
        let key = format!("{db}|{session}");
        let mut r = self.reserved.lock().unwrap();
        if !r.is_empty() && !r.contains(&key) {
            return Err(ProxyError::Db("BUSY".into()));
        }
        r.insert(key);
        Ok(json!({"ok": true}))
    }
    async fn release(&self, db: &str, session: &str) -> Result<Value, ProxyError> {
        self.reserved.lock().unwrap().remove(&format!("{db}|{session}"));
        Ok(json!({"ok": true}))
    }
    async fn query(&self, _: &str, _: &str, _: Vec<Value>, _: bool) -> Result<Value, ProxyError> {
        Ok(json!({"rows": []}))
    }
    async fn write(&self, _: &str, _: &str, _: &str, _: Vec<Value>) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn status(&self, _: Option<&str>) -> Result<Value, ProxyError> {
        Ok(json!([]))
    }
    async fn schema(&self, _: &str) -> Result<Value, ProxyError> {
        Ok(json!({"tables": []}))
    }
    async fn blob_session_begin(&self, _: &str, _: &str, _: &str, _: &str) -> Result<Value, ProxyError> {
        let mut n = self.next.lock().unwrap();
        *n += 1;
        let sid = format!("mem-{n}");
        self.sessions.lock().unwrap().insert(sid.clone(), Vec::new());
        self.frames.lock().unwrap().insert(sid.clone(), 0);
        Ok(json!({"session_id": sid}))
    }
    async fn blob_session_append(&self, _: &str, _: &str, sid: &str, data: &[u8], _: u64) -> Result<Value, ProxyError> {
        self.sessions.lock().unwrap().get_mut(sid).ok_or_else(|| ProxyError::Db("session".into()))?.extend_from_slice(data);
        *self.frames.lock().unwrap().get_mut(sid).unwrap() += 1;
        Ok(json!({"ok": true}))
    }
    async fn blob_session_finish(&self, _: &str, _: &str, sid: &str) -> Result<Value, ProxyError> {
        // Retention-frei: Hash bilden, Puffer FREIGEBEN (RSS bleibt flach).
        let bytes = self.sessions.lock().unwrap().remove(sid).unwrap_or_default();
        let frames = self.frames.lock().unwrap().remove(sid).unwrap_or(0);
        Ok(json!({"session_id": sid, "gesamt_sha256": hex::encode(Sha256::digest(&bytes)), "chunk_ids": vec!["x"; frames as usize]}))
    }
    async fn blob_session_get(&self, _: &str, _: &str, sid: &str) -> Result<Vec<u8>, ProxyError> {
        Ok(self.sessions.lock().unwrap().get(sid).cloned().unwrap_or_default())
    }
}
