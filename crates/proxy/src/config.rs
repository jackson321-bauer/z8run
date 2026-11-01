//! Proxy-Konfiguration (eine Quelle fuer Defaults/Env).

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub login_socket: PathBuf,
    pub admin_socket: PathBuf,
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
    pub stream_subscribers: usize,
    pub stream_sub_queue: usize,
    pub stream_claim_grace_ms: u64,
    pub stream_frame_max: usize,
    pub stream_channels_per_session: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Self {
            login_socket: PathBuf::from(env("KV_PROXY_LOGIN_SOCK", "/data/z8run/kv3-proxy.sock")),
            admin_socket: PathBuf::from(env("KV_PROXY_ADMIN_SOCK", "/data/z8run/kv-proxy-admin.sock")),
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
            stream_subscribers: env("KV_PROXY_STREAM_SUBS", "32").parse().unwrap_or(32),
            stream_sub_queue: env("KV_PROXY_STREAM_QUEUE", "256").parse().unwrap_or(256),
            stream_claim_grace_ms: env("KV_PROXY_STREAM_GRACE_MS", "5000")
                .parse()
                .unwrap_or(5000),
            stream_frame_max: env("KV_PROXY_STREAM_FRAME_MAX", "1048576")
                .parse()
                .unwrap_or(1_048_576),
            stream_channels_per_session: env("KV_PROXY_STREAM_CHANNELS", "64")
                .parse()
                .unwrap_or(64),
        }
    }
}

