//! Nativ-Proxy-Dienst: verbindet Kern-Logik mit Adaptern.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use proxy_kern::{
    Clock, DbPort, PromptStore, ProxyError, Random, SessionInfo, SessionState, SessionStore,
    TokenConfig, TokenGrant, TokenManager,
};
use serde_json::Value;

use crate::adapters::{OsRandom, SystemClock};

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub login_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub http_bind: String,
    pub http_port: u16,
    pub token_ttl_ms: u64,
    pub token_grace_ms: u64,
    pub bundle: String,
    pub dbnode_dir: PathBuf,
    pub db_socket: PathBuf,
    pub cluster_id: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Self {
            login_socket: PathBuf::from(env("KV_PROXY_LOGIN_SOCK", "/data/z8run/kv3-proxy.sock")),
            admin_socket: PathBuf::from(env("KV_PROXY_ADMIN_SOCK", "/data/z8run/kv-proxy-admin.sock")),
            http_bind: env("KV_PROXY_BIND", "127.0.0.1"),
            http_port: env("KV_PROXY_PORT", "7800").parse().unwrap_or(7800),
            token_ttl_ms: env("KV_PROXY_TOKEN_TTL_MS", "900000").parse().unwrap_or(900_000),
            token_grace_ms: env("KV_PROXY_TOKEN_GRACE_MS", "30000").parse().unwrap_or(30_000),
            bundle: env("KV_PROXY_BUNDLE", "/data/z8run/proxy-bundle"),
            dbnode_dir: PathBuf::from(env("KV_PROXY_DBNODE_DIR", "/data/z8run/dbnode")),
            db_socket: PathBuf::from(env("Z8_DBNODE_SOCK", "/data/z8run/dbnode-msg.sock")),
            cluster_id: env("KV_PROXY_CLUSTER_ID", "default"),
        }
    }
}

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

pub struct ProxyService {
    pub cfg: ProxyConfig,
    pub clock: Arc<dyn Clock>,
    pub sessions: SessionStore,
    pub tokens: TokenManager,
    pub prompts: PromptStore,
    pub db: Arc<dyn DbPort>,
}

impl ProxyService {
    pub fn new(cfg: ProxyConfig) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let random: Arc<dyn Random> = Arc::new(OsRandom);
        Self::with_parts(cfg, clock, random)
    }

    pub fn with_parts(cfg: ProxyConfig, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Self {
        let tokens = TokenManager::new(
            TokenConfig {
                ttl_ms: cfg.token_ttl_ms,
                grace_ms: cfg.token_grace_ms,
            },
            clock.clone(),
            random,
        );
        Self {
            cfg,
            clock,
            sessions: SessionStore::new(),
            tokens,
            prompts: PromptStore::new(),
            db: Arc::new(NoDb),
        }
    }

    pub fn with_db(mut self, db: Arc<dyn DbPort>) -> Self {
        self.db = db;
        self
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn open_session(&self, state: SessionState) -> TokenGrant {
        let sid = state.session_id.clone();
        self.sessions.insert(state);
        self.tokens.issue(&sid)
    }

    pub fn authenticate(&self, token: &str) -> Result<SessionInfo, ProxyError> {
        let sid = self.tokens.validate(token)?;
        let now = self.now_ms();
        self.sessions
            .with(&sid, |s| {
                s.touch(now);
                SessionInfo::from(&*s)
            })
            .ok_or(ProxyError::Unauthorized)
    }

    pub fn rotate(&self, token: &str) -> Result<TokenGrant, ProxyError> {
        let grant = self.tokens.rotate(token)?;
        let now = self.now_ms();
        let _ = self.sessions.with(&grant.session_id, |s| s.touch(now));
        Ok(grant)
    }

    pub fn logout(&self, token: &str) -> Result<(), ProxyError> {
        let sid = self.tokens.logout(token)?;
        let removed = self.sessions.remove(&sid);
        if removed.is_some() {
            self.tokens.revoke_session(&sid);
        }
        Ok(())
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "sessions": self.sessions.count(),
            "active_tokens": self.tokens.active_count(),
            "prompts": self.prompts.len(),
        })
    }
}
