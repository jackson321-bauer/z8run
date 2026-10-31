//! Nativ-Proxy-Dienst: verbindet Kern-Logik mit Adaptern.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use proxy_kern::{
    meta::EventKind, Clock, DbPort, LlmPort, MetaEvent, PromptStore, ProxyError, Random,
    SessionInfo, SessionState, SessionStore, TokenConfig, TokenGrant, TokenManager, TraceContext,
};

use crate::meta::MetaStore;
use crate::secrets::SecretStore;
use crate::otel::OtelStore;
use crate::subscribe::{Event, EventHub, Filter, Sink};
use crate::wal_guard::WalGuard;
use serde_json::Value;

use crate::adapters::{OsRandom, SystemClock};
use crate::apps::{AppRegistry, MockLlm};

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
    pub otel_db: String,
    pub meta_db: String,
    pub cluster_meta_db: String,
    pub wal_pending_limit: u64,
    pub export_dir: PathBuf,
    pub export_key: String,
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
            otel_db: env("KV_PROXY_OTEL_DB", "otel"),
            meta_db: env("KV_PROXY_META_DB", "meta"),
            cluster_meta_db: env("KV_PROXY_CLUSTER_META_DB", "meta-cluster"),
            wal_pending_limit: env("KV_PROXY_WAL_PENDING_LIMIT", "1000")
                .parse()
                .unwrap_or(1000),
            export_dir: PathBuf::from(env("KV_PROXY_EXPORT_DIR", "/data/z8run/exports/otel")),
            export_key: env("KV_PROXY_EXPORT_KEY", ""),
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
    pub apps: AppRegistry,
    pub llm: Arc<dyn LlmPort>,
    pub otel: Option<Arc<OtelStore>>,
    pub meta: Option<Arc<MetaStore>>,
    pub hub: Arc<EventHub>,
    pub guard: Arc<WalGuard>,
    pub secrets: SecretStore,
}

/// Logging-Persistenz als Abonnent der Subscribe/Push-Naht.
struct LoggingSink {
    meta: Arc<MetaStore>,
    otel: Arc<OtelStore>,
}

#[async_trait]
impl Sink for LoggingSink {
    async fn deliver(&self, event: &Event) -> bool {
        if event.kind.starts_with("meta:") {
            if let Some(v) = event.payload.get("meta") {
                match serde_json::from_value::<MetaEvent>(v.clone()) {
                    Ok(m) => {
                        if let Err(e) = self.meta.record(&m).await {
                            tracing::warn!(code = e.code(), art = m.action, "Meta-Schreiben fehlgeschlagen");
                            return false;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Meta-Abonnent: Payload unlesbar");
                        return false;
                    }
                }
            }
        } else if event.kind.starts_with("otel:") {
            if let Some(v) = event.payload.get("span") {
                match serde_json::from_value::<proxy_kern::Span>(v.clone()) {
                    Ok(span) => {
                        if let Err(e) = self.otel.write(&span).await {
                            tracing::warn!(code = e.code(), "Span-Schreiben fehlgeschlagen");
                            return false;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "OTel-Abonnent: Payload unlesbar");
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl ProxyService {
    pub fn new(cfg: ProxyConfig) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let random: Arc<dyn Random> = Arc::new(OsRandom);
        Self::with_parts(cfg, clock, random)
    }

    pub fn with_parts(cfg: ProxyConfig, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Self {
        let wal_limit = cfg.wal_pending_limit;
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
            apps: AppRegistry::new(),
            llm: Arc::new(MockLlm),
            otel: None,
            meta: None,
            hub: Arc::new(EventHub::default()),
            guard: WalGuard::new(wal_limit),
            secrets: SecretStore::new(),
        }
    }

    pub fn with_db(mut self, db: Arc<dyn DbPort>) -> Self {
        let otel = Arc::new(OtelStore::new(db.clone(), self.cfg.otel_db.clone()));
        let mut meta_dbs = vec![self.cfg.meta_db.clone()];
        if self.cfg.cluster_meta_db != self.cfg.meta_db {
            meta_dbs.push(self.cfg.cluster_meta_db.clone());
        }
        let meta = Arc::new(MetaStore::new(db.clone(), meta_dbs));
        // Logging ist ein ECHTER Abonnent der Naht: jedes Meta-/OTel-Ereignis
        // wird publiziert und von diesem Sink in die DB geschrieben.
        self.hub.subscribe(
            Filter::all(),
            Arc::new(LoggingSink {
                meta: meta.clone(),
                otel: otel.clone(),
            }),
        );
        self.db = db;
        self.otel = Some(otel);
        self.meta = Some(meta);
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

    /// Interner Logging-DB-Satz (otel + meta) fuer Login/Open-Scope.
    pub fn logging_dbs(&self) -> Vec<String> {
        let mut v = vec![self.cfg.otel_db.clone(), self.cfg.meta_db.clone()];
        if !v.contains(&self.cfg.cluster_meta_db) {
            v.push(self.cfg.cluster_meta_db.clone());
        }
        v
    }

    /// Jede Aktion erzeugt mind. einen Meta-Eintrag (best effort, nie
    /// inhaltlich: detail ist Kurz-Kontext).
    pub async fn record_meta(
        &self,
        actor: &str,
        kind: EventKind,
        object_ref: &str,
        trace_id: &str,
        session: &str,
        status: &str,
        detail: &str,
    ) {
        let event = match MetaEvent::new(
            actor,
            kind,
            object_ref,
            trace_id,
            session,
            status,
            detail,
            self.now_ms(),
        ) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(code = e.code(), "Meta-Ereignis ungueltig");
                return;
            }
        };
        // Logging ist erster Abonnent an der Naht (kein Sonderpfad).
        let payload = serde_json::json!({
            "meta": serde_json::to_value(&event).unwrap_or(Value::Null)
        });
        self.hub
            .publish(
                &self.cfg.cluster_id,
                "proxy",
                &format!("meta:{}", event.action),
                trace_id,
                payload,
            )
            .await;
    }

    /// Proxy garantiert Trace: gueltiger eingehender Kontext wird
    /// durchgereicht, sonst selbst erzeugt+injiziert.
    pub fn ensure_trace(&self, incoming: Option<&str>) -> (TraceContext, bool) {
        let random = crate::adapters::OsRandom;
        proxy_kern::otel::ensure_context(incoming, &random)
    }

    pub async fn write_span(&self, span: proxy_kern::Span) {
        let payload = serde_json::json!({
            "span": serde_json::to_value(&span).unwrap_or(Value::Null)
        });
        self.hub
            .publish(
                &self.cfg.cluster_id,
                "proxy",
                &format!("otel:{}", span.name),
                &span.trace_id,
                payload,
            )
            .await;
    }

    /// Fail-closed: sobald die WAL nicht sicher ist, kein Verkehr mehr.
    pub fn wal_down(&self) -> bool {
        self.guard.is_down()
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "sessions": self.sessions.count(),
            "active_tokens": self.tokens.active_count(),
            "prompts": self.prompts.len(),
            "apps": self.apps.len(),
        })
    }
}
