//! Session-Scope: DBs, Apps und Masterkey NUR im RAM (zeroize beim Drop).

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::ProxyError;

pub struct SessionState {
    pub session_id: String,
    pub addr_space: String,
    pub addr_user: String,
    pub workspace_bucket: String,
    pub engines: Value,
    pub dbs: Vec<String>,
    pub apps: Vec<String>,
    master: Zeroizing<Vec<u8>>,
    pub created_ms: u64,
    pub last_seen_ms: u64,
}

impl SessionState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        addr_space: String,
        addr_user: String,
        workspace_bucket: String,
        engines: Value,
        dbs: Vec<String>,
        master: Vec<u8>,
        now_ms: u64,
    ) -> Self {
        Self {
            session_id,
            addr_space,
            addr_user,
            workspace_bucket,
            engines,
            dbs,
            apps: Vec::new(),
            master: Zeroizing::new(master),
            created_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }

    pub fn in_scope(&self, db_id: &str) -> bool {
        self.dbs.iter().any(|d| d == db_id)
    }

    pub fn master_bytes(&self) -> &[u8] {
        &self.master
    }

    /// Nur fuer den DB-Client; der Aufrufer darf den Wert nie loggen.
    pub fn master_b64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.master.as_slice())
    }

    pub fn touch(&mut self, now_ms: u64) {
        self.last_seen_ms = now_ms;
    }

    pub fn add_app(&mut self, name: &str) {
        if !self.apps.iter().any(|a| a == name) {
            self.apps.push(name.to_string());
        }
    }
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("session_id", &self.session_id)
            .field("addr_space", &self.addr_space)
            .field("addr_user", &self.addr_user)
            .field("workspace_bucket", &self.workspace_bucket)
            .field("dbs", &self.dbs)
            .field("apps", &self.apps)
            .field("master", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub addr_space: String,
    pub addr_user: String,
    pub workspace_bucket: String,
    pub dbs: Vec<String>,
    pub apps: Vec<String>,
    pub created_ms: u64,
    pub last_seen_ms: u64,
}

impl From<&SessionState> for SessionInfo {
    fn from(s: &SessionState) -> Self {
        Self {
            session_id: s.session_id.clone(),
            addr_space: s.addr_space.clone(),
            addr_user: s.addr_user.clone(),
            workspace_bucket: s.workspace_bucket.clone(),
            dbs: s.dbs.clone(),
            apps: s.apps.clone(),
            created_ms: s.created_ms,
            last_seen_ms: s.last_seen_ms,
        }
    }
}

/// RAM-Registry aller offenen Sessions. Kein Master in Debug/Serialisierung.
#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, state: SessionState) {
        let sid = state.session_id.clone();
        self.inner().insert(sid, state);
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, HashMap<String, SessionState>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Fuehrt eine synchrone Operation unter dem Lock aus (nie ueber await).
    pub fn with<R>(&self, session_id: &str, f: impl FnOnce(&mut SessionState) -> R) -> Option<R> {
        self.inner().get_mut(session_id).map(f)
    }

    pub fn remove(&self, session_id: &str) -> Option<SessionState> {
        self.inner().remove(session_id)
    }

    pub fn info(&self, session_id: &str) -> Result<SessionInfo, ProxyError> {
        self.inner()
            .get(session_id)
            .map(SessionInfo::from)
            .ok_or(ProxyError::Unauthorized)
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        self.inner().values().map(SessionInfo::from).collect()
    }

    pub fn count(&self) -> usize {
        self.inner().len()
    }

    /// Prueft den DB-Scope einer Session ohne den Master zu kopieren.
    pub fn in_scope(&self, session_id: &str, db_id: &str) -> Result<bool, ProxyError> {
        self.inner()
            .get(session_id)
            .map(|s| s.in_scope(db_id))
            .ok_or(ProxyError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SessionState {
        SessionState::new(
            "s1".into(),
            "space".into(),
            "user".into(),
            "ws/".into(),
            Value::Null,
            vec!["db1".into()],
            b"geheim".to_vec(),
            1,
        )
    }

    #[test]
    fn scope_wird_durchgesetzt() {
        let s = state();
        assert!(s.in_scope("db1"));
        assert!(!s.in_scope("db2"));
    }

    #[test]
    fn debug_enthaelt_keinen_master() {
        let s = state();
        let text = format!("{s:?}");
        assert!(text.contains("redacted"));
        assert!(!text.contains("geheim"));
    }

    #[test]
    fn store_info_ohne_master() {
        let store = SessionStore::new();
        store.insert(state());
        let info = store.info("s1").unwrap();
        let text = serde_json::to_string(&info).unwrap();
        assert!(!text.contains("geheim"));
        assert!(info.dbs.contains(&"db1".to_string()));
    }
}
