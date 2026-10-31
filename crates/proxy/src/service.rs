//! Nativ-Proxy-Dienst: verbindet Kern-Logik mit Adaptern.

use std::sync::Arc;

use proxy_kern::{
    Clock, DbPort, LlmPort, PromptStore, ProxyError, Random, SessionInfo, SessionState,
    SessionStore, TokenConfig, TokenGrant, TokenManager,
};

use crate::channel::{ChannelConfig, ChannelRegistry};
use crate::config::ProxyConfig;
use crate::logging_sink::LoggingSink;
use crate::nodb::NoDb;
use crate::meta::MetaStore;
use crate::secrets::SecretStore;
use crate::otel::OtelStore;
use crate::subscribe::{EventHub, Filter};
use crate::wal_guard::WalGuard;

use crate::adapters::{OsRandom, SystemClock};
use crate::apps::{AppRegistry, MockLlm};

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
    pub streams: Arc<ChannelRegistry>,
    pub recordings: std::sync::Mutex<std::collections::HashMap<String, Arc<crate::recording::Recording>>>,
}

impl ProxyService {
    pub fn new(cfg: ProxyConfig) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let random: Arc<dyn Random> = Arc::new(OsRandom);
        Self::with_parts(cfg, clock, random)
    }

    pub fn with_parts(cfg: ProxyConfig, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Self {
        let wal_limit = cfg.wal_pending_limit;
        let streams = Arc::new(ChannelRegistry::new(
            ChannelConfig {
                subscribers_per_channel: cfg.stream_subscribers,
                channels_per_session: crate::channel::CHANNELS_PER_SESSION,
                claim_grace_ms: cfg.stream_claim_grace_ms,
                sub_queue: cfg.stream_sub_queue,
                max_frame_bytes: cfg.stream_frame_max,
            },
            clock.clone(),
        ));
        let tokens = TokenManager::new(
            TokenConfig {
                ttl_ms: cfg.token_ttl_ms,
                grace_ms: cfg.token_grace_ms,
            },
            clock.clone(),
            random,
        );
        let hub = Arc::new(EventHub::default());
        let svc = Self {
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
            hub: hub.clone(),
            guard: WalGuard::new(wal_limit),
            secrets: SecretStore::new(),
            streams,
            recordings: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        // G5: Overflow wird zentral gemeldet (WS, Node, Playback, CTL gleich).
        let cluster = svc.cfg.cluster_id.clone();
        let sink_hub = hub;
        svc.streams.set_overflow_sink(Arc::new(move |channel, dropped| {
            let event = proxy_kern::meta::MetaEvent {
                actor: "system".into(),
                action: "stream_overflow".into(),
                object_ref: channel.to_string(),
                trace_id: String::new(),
                session: "proxy".into(),
                status: "ok".into(),
                detail: format!("stream_overflow dropped={dropped}"),
                ts_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            };
            if event.validate().is_err() {
                return;
            }
            let payload = serde_json::json!({
                "meta": serde_json::to_value(&event).unwrap_or(serde_json::Value::Null)
            });
            let hub = sink_hub.clone();
            let cluster = cluster.clone();
            tokio::spawn(async move {
                hub.publish(&cluster, "proxy", "meta:stream_overflow", "", payload)
                    .await;
            });
        }));
        svc
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
