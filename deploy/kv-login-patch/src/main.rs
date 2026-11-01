//! KronVault login API.
//!
//! One HTTP API, three clients: UI, CLI and MCP all call the same endpoints.
//! The master key never leaves this process; the client gets a short-lived
//! session token and a SHA-256 fingerprint of the master key.

mod udsv3;
mod udsv3_stream;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Parser;
use hkdf::Hkdf;
use kv_login::kette;
use kv_store::s3::S3Endpoint;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "kv-login", about = "KronVault login API (UI/CLI/MCP)")]
struct Args {
    /// Local Argon2IDHashDatei/2 or a fixture containing hash_datei.
    #[arg(long)]
    hash_file: Option<PathBuf>,
    /// S3 config (host, region, access_key, secret_key, optional bucket/prefix).
    /// Without bucket, the derived space address is used as the bucket name.
    #[arg(long)]
    s3_config: Option<PathBuf>,
    /// Salt for the Argon2id address chain. Required for a raw hash file.
    #[arg(long, env = "KV_LOGIN_SALT")]
    salt: Option<String>,
    /// Optional JSON map {"17":"salt-epoch-17",...} for older hash entries.
    #[arg(long)]
    salt_epochs: Option<PathBuf>,
    /// Expected space address; requests for another space are rejected.
    #[arg(long)]
    space_addr: Option<String>,
    /// Unix-Domain-Socket (PORT-KILL: kein interner TCP-Port).
    #[arg(long, default_value = "/data/z8run/kv-login.sock")]
    uds: PathBuf,
    /// Nur fuer lokale Debug-Laeufe: zusaetzlicher TCP-Listener.
    #[arg(long)]
    bind: Option<String>,
    /// Session lifetime in seconds (auto-lock).
    #[arg(long, default_value_t = 60)]
    session_ttl: u64,
}

#[derive(Clone)]
struct S3Config {
    host: String,
    region: String,
    access_key: String,
    secret_key: String,
    bucket: Option<String>,
    prefix: Option<String>,
}

#[derive(Clone)]
struct HashSource {
    file: Option<PathBuf>,
    s3: Option<S3Config>,
    static_hash: Option<Value>,
}

impl HashSource {
    async fn load(&self, space_addr: &str) -> Result<Value, String> {
        if let Some(hash) = &self.static_hash {
            return Ok(hash.clone());
        }
        if let Some(path) = &self.file {
            let raw = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| format!("Hashdatei {}: {e}", path.display()))?;
            let doc: Value =
                serde_json::from_str(&raw).map_err(|e| format!("Hashdatei JSON: {e}"))?;
            let hash = doc.get("hash_datei").cloned().unwrap_or(doc);
            if let Some(expected) = hash.get("space_addr").and_then(|v| v.as_str()) {
                if expected != space_addr {
                    return Err("Space-Adresse passt nicht zur Hashdatei".to_string());
                }
            }
            return Ok(hash);
        }
        if let Some(cfg) = &self.s3 {
            let endpoint = S3Endpoint {
                host: cfg.host.clone(),
                region: cfg.region.clone(),
                access_key: cfg.access_key.clone(),
                secret_key: cfg.secret_key.clone(),
            };
            let bucket = cfg.bucket.clone().unwrap_or_else(|| space_addr.to_string());
            let prefix = cfg.prefix.clone().unwrap_or_default();
            let key = format!("{prefix}Argon2IDHashDatei.txt");
            let data = endpoint
                .get_object(&bucket, &key)
                .await
                .map_err(|e| format!("S3 GET {bucket}/{key}: {e}"))?;
            let doc: Value =
                serde_json::from_slice(&data).map_err(|e| format!("Hashdatei JSON: {e}"))?;
            return Ok(doc.get("hash_datei").cloned().unwrap_or(doc));
        }
        Err("Keine Hashdatei-Quelle konfiguriert (--hash-file oder --s3-config)".to_string())
    }
}

#[cfg(unix)]
fn mlock_bytes(b: &[u8]) -> bool {
    extern "C" {
        fn mlock(addr: *const std::os::raw::c_void, len: usize) -> std::os::raw::c_int;
    }
    !b.is_empty() && unsafe { mlock(b.as_ptr() as *const _, b.len()) == 0 }
}

#[cfg(unix)]
fn munlock_bytes(b: &[u8]) {
    extern "C" {
        fn munlock(addr: *const std::os::raw::c_void, len: usize) -> std::os::raw::c_int;
    }
    if !b.is_empty() {
        unsafe {
            let _ = munlock(b.as_ptr() as *const _, b.len());
        }
    }
}

#[cfg(not(unix))]
fn mlock_bytes(_b: &[u8]) -> bool { false }
#[cfg(not(unix))]
fn munlock_bytes(_b: &[u8]) {}

struct Session {
    #[allow(dead_code)]
    master: Zeroizing<Vec<u8>>,
    mlocked: bool,
    username: String,
    space_addr: String,
    user_addr: String,
    /// Decrypted passbox S3 credentials. Kept in RAM only; never logged.
    s3: Option<Value>,
    /// Bucket/prefix list from the passbox payload.
    buckets: Option<Value>,
    last_seen: Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master.zeroize();
        if self.mlocked {
            munlock_bytes(&self.master);
        }
    }
}

#[derive(Clone)]
struct AppState {
    source: HashSource,
    salt: String,
    salt_epochs: Arc<BTreeMap<String, String>>,
    expected_space: Option<String>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    attempts: Arc<Mutex<Vec<Instant>>>,
    ttl: Duration,
    internal_key: Option<String>,
    started: Instant,
}

#[derive(Deserialize)]
struct SpaceReq {
    space: String,
}

#[derive(Deserialize)]
struct LoginReq {
    space: String,
    username: String,
    password: String,
    /// PEM text of the user's hardware key (SEC1). The CLI reads the file and
    /// sends the text; the API never reads arbitrary server paths.
    key_pem: String,
}

fn problem(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "ok": false, "error": msg.into() }))).into_response()
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn health(State(state): State<AppState>) -> Response {
    let sessions = state.sessions.lock().await.len();
    let schema = state
        .source
        .static_hash
        .as_ref()
        .and_then(|h| h.get("schema"))
        .and_then(|v| v.as_str())
        .unwrap_or("dynamic");
    Json(json!({
        "ok": true,
        "service": "kv-login",
        "schema": schema,
        "salt_configured": !state.salt.is_empty(),
        "space_addr": state.expected_space,
        "sessions": sessions,
        "uptime_secs": state.started.elapsed().as_secs(),
    }))
    .into_response()
}

async fn space(State(state): State<AppState>, Json(req): Json<SpaceReq>) -> Response {
    let addr = match kette::adresse(&req.space, &state.salt) {
        Ok(v) => v,
        Err(e) => return problem(StatusCode::BAD_REQUEST, e),
    };
    if let Some(expected) = &state.expected_space {
        if expected != &addr {
            return problem(StatusCode::NOT_FOUND, "B2BSpace nicht gefunden");
        }
    }
    match state.source.load(&addr).await {
        Ok(hash) => {
            let users = hash
                .get("users")
                .and_then(|v| v.as_object())
                .map(|m| m.len())
                .unwrap_or(0);
            Json(json!({
                "ok": true,
                "space": req.space,
                "space_addr": addr,
                "hash_found": true,
                "users": users,
            }))
            .into_response()
        }
        Err(e) => problem(StatusCode::NOT_FOUND, e),
    }
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    // Cheap global rate limit: 30 attempts per rolling minute.
    {
        let mut attempts = state.attempts.lock().await;
        let cutoff = Instant::now() - Duration::from_secs(60);
        attempts.retain(|t| *t > cutoff);
        if attempts.len() >= 30 {
            return problem(StatusCode::TOO_MANY_REQUESTS, "Zu viele Login-Versuche");
        }
        attempts.push(Instant::now());
    }

    let password = Zeroizing::new(req.password);
    let key_pem = Zeroizing::new(req.key_pem);
    if password.is_empty() || key_pem.trim().is_empty() {
        return problem(StatusCode::BAD_REQUEST, "Passwort und Hardwarekey sind Pflicht");
    }

    let space_addr = match kette::adresse(&req.space, &state.salt) {
        Ok(v) => v,
        Err(e) => return problem(StatusCode::BAD_REQUEST, e),
    };
    if let Some(expected) = &state.expected_space {
        if expected != &space_addr {
            return problem(StatusCode::NOT_FOUND, "B2BSpace nicht gefunden");
        }
    }

    let hash = match state.source.load(&space_addr).await {
        Ok(v) => v,
        Err(e) => return problem(StatusCode::NOT_FOUND, e),
    };
    let user_addr = match kette::adresse(&req.username, &state.salt) {
        Ok(v) => v,
        Err(e) => return problem(StatusCode::BAD_REQUEST, e),
    };
    let user_key = format!("login:{user_addr}");
    let entry = &hash["users"][&user_key];
    if entry.is_null() {
        return problem(
            StatusCode::UNAUTHORIZED,
            "Username in diesem B2BSpace nicht gefunden",
        );
    }

    let mut epochs = (*state.salt_epochs).clone();
    if let Some(epoch) = entry.get("epoche").and_then(|v| v.as_u64()) {
        epochs
            .entry(epoch.to_string())
            .or_insert_with(|| state.salt.clone());
    }
    let epochen = if epochs.is_empty() { None } else { Some(&epochs) };

    let login = match kette::login_aus_datei_mit_epochen(
        &hash,
        &space_addr,
        &req.username,
        password.as_str(),
        key_pem.as_str(),
        &state.salt,
        epochen,
    ) {
        Ok(v) => v,
        Err(e) => return problem(StatusCode::UNAUTHORIZED, e),
    };

    let master_fingerprint = hex::encode(Sha256::digest(&login.master_key));
    let token = new_token();
    let mlocked = mlock_bytes(&login.master_key);
    let session = Session {
        master: Zeroizing::new(login.master_key),
        mlocked,
        username: login.username.clone(),
        space_addr: login.space_addr.clone(),
        user_addr: login.user_addr.clone(),
        s3: login.passbox_payload.get("s3").cloned(),
        buckets: login.passbox_payload.get("buckets").cloned(),
        last_seen: Instant::now(),
    };
    state.sessions.lock().await.insert(token.clone(), session);

    Json(json!({
        "ok": true,
        "token": token,
        "username": login.username,
        "space_addr": login.space_addr,
        "user_addr": login.user_addr,
        "master_sha256": master_fingerprint,
        "expires_in": state.ttl.as_secs(),
    }))
    .into_response()
}

async fn session(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let mut sessions = state.sessions.lock().await;
    let Some(s) = sessions.get_mut(&token) else {
        return problem(StatusCode::UNAUTHORIZED, "Session unbekannt oder abgelaufen");
    };
    if s.last_seen.elapsed() > state.ttl {
        sessions.remove(&token);
        return problem(StatusCode::UNAUTHORIZED, "Session abgelaufen");
    }
    s.last_seen = Instant::now();
    let remaining = state.ttl.as_secs().saturating_sub(s.last_seen.elapsed().as_secs());
    Json(json!({
        "ok": true,
        "username": s.username,
        "space_addr": s.space_addr,
        "user_addr": s.user_addr,
        "locked": false,
        "expires_in": remaining,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct TokenReq {
    token: String,
}

async fn touch(State(state): State<AppState>, Json(req): Json<TokenReq>) -> Response {
    let mut sessions = state.sessions.lock().await;
    let Some(s) = sessions.get_mut(&req.token) else {
        return problem(StatusCode::UNAUTHORIZED, "Session unbekannt oder abgelaufen");
    };
    if s.last_seen.elapsed() > state.ttl {
        sessions.remove(&req.token);
        return problem(StatusCode::UNAUTHORIZED, "Session abgelaufen");
    }
    s.last_seen = Instant::now();
    Json(json!({ "ok": true, "expires_in": state.ttl.as_secs() })).into_response()
}

async fn logout(State(state): State<AppState>, Json(req): Json<TokenReq>) -> Response {
    let removed = state.sessions.lock().await.remove(&req.token).is_some();
    Json(json!({ "ok": true, "removed": removed })).into_response()
}

#[derive(Deserialize)]
struct DeriveReq {
    token: String,
    db: String,
}

/// Derives a per-database SQLCipher key from the in-RAM master.
/// Internal only: requires the `x-kv-internal` header; the master never leaves
/// this process and the derived key is not persisted.
async fn derive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeriveReq>,
) -> Response {
    let Some(expected) = state.internal_key.as_deref() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "derive disabled");
    };
    let supplied = headers
        .get("x-kv-internal")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if supplied != expected {
        return problem(StatusCode::UNAUTHORIZED, "internal header fehlt");
    }
    let db = req.db.trim();
    if db.is_empty()
        || db.len() > 128
        || !db
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return problem(StatusCode::BAD_REQUEST, "db-Name ungültig");
    }

    let mut sessions = state.sessions.lock().await;
    let Some(s) = sessions.get_mut(&req.token) else {
        return problem(StatusCode::UNAUTHORIZED, "Session unbekannt oder abgelaufen");
    };
    if s.last_seen.elapsed() > state.ttl {
        sessions.remove(&req.token);
        return problem(StatusCode::UNAUTHORIZED, "Session abgelaufen");
    }

    let hk = Hkdf::<Sha256>::new(Some(b"kronvault-db-key-v1"), s.master.as_slice());
    let mut key = [0u8; 32];
    if hk.expand(db.as_bytes(), &mut key).is_err() {
        return problem(StatusCode::INTERNAL_SERVER_ERROR, "HKDF fehlgeschlagen");
    }
    s.last_seen = Instant::now();

    Json(json!({
        "ok": true,
        "db": db,
        "alg": "HKDF-SHA256",
        "key_hex": hex::encode(key),
        "user_addr": s.user_addr,
        "space_addr": s.space_addr,
        "s3": s.s3.clone(),
        "buckets": s.buckets.clone(),
    }))
    .into_response()
}

async fn ui() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let doc = if let Some(path) = &args.hash_file {
        let raw = tokio::fs::read_to_string(path).await?;
        serde_json::from_str::<Value>(&raw)?
    } else {
        Value::Null
    };
    let static_hash = if doc.is_null() {
        None
    } else {
        Some(doc.get("hash_datei").cloned().unwrap_or(doc.clone()))
    };
    let salt = args
        .salt
        .clone()
        .or_else(|| doc.get("salt").and_then(|v| v.as_str()).map(str::to_string))
        .ok_or("Salt fehlt (--salt oder KV_LOGIN_SALT)")?;
    let expected_space = args
        .space_addr
        .clone()
        .or_else(|| doc.get("space_addr").and_then(|v| v.as_str()).map(str::to_string));

    let salt_epochs = if let Some(path) = &args.salt_epochs {
        let raw = tokio::fs::read_to_string(path).await?;
        let map: BTreeMap<String, String> = serde_json::from_str(&raw)?;
        Arc::new(map)
    } else {
        Arc::new(BTreeMap::new())
    };

    let s3 = if let Some(path) = &args.s3_config {
        let raw = tokio::fs::read_to_string(path).await?;
        let v: Value = serde_json::from_str(&raw)?;
        Some(S3Config {
            host: v["host"].as_str().ok_or("s3 host fehlt")?.to_string(),
            region: v["region"].as_str().unwrap_or("").to_string(),
            access_key: v["access_key"].as_str().ok_or("s3 access_key fehlt")?.to_string(),
            secret_key: v["secret_key"].as_str().ok_or("s3 secret_key fehlt")?.to_string(),
            bucket: v["bucket"].as_str().map(|s| s.to_string()),
            prefix: v["prefix"].as_str().map(|s| s.to_string()),
        })
    } else {
        None
    };
    if static_hash.is_none() && s3.is_none() {
        return Err("Entweder --hash-file oder --s3-config angeben".into());
    }

    let state = AppState {
        source: HashSource {
            file: args.hash_file.clone(),
            s3,
            static_hash,
        },
        salt,
        salt_epochs,
        expected_space,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        attempts: Arc::new(Mutex::new(Vec::new())),
        ttl: Duration::from_secs(args.session_ttl.max(5)),
        internal_key: std::env::var("KV_LOGIN_INTERNAL_KEY")
            .ok()
            .filter(|s| !s.is_empty()),
        started: Instant::now(),
    };

    // Auto-lock: drop expired sessions and zeroize their master keys.
    {
        let sessions = state.sessions.clone();
        let ttl = state.ttl;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                sessions
                    .lock()
                    .await
                    .retain(|_, s| s.last_seen.elapsed() <= ttl);
            }
        });
    }

    let app = Router::new()
        .route("/", get(ui))
        .route("/v1/health", get(health))
        .route("/v1/space", post(space))
        .route("/v1/login", post(login))
        .route("/v1/session/{token}", get(session))
        .route("/v1/touch", post(touch))
        .route("/v1/derive", post(derive))
        .route("/v1/logout", post(logout))
        .with_state(state);

    if let Some(bind) = &args.bind {
        let addr: SocketAddr = bind.parse()?;
        tracing::warn!(%addr, "kv-login Debug-TCP aktiv (nicht fuer Deployment)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let debug_app = app.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, debug_app).await;
        });
    }

    let uds_path = args.uds.clone();
    if let Some(parent) = uds_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = tokio::fs::remove_file(&uds_path).await;
    let uds = tokio::net::UnixListener::bind(&uds_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&uds_path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(path = %uds_path.display(), "kv-login API ready (UDS/udsv3)");
    loop {
        let (stream, _) = uds.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let io = match udsv3_stream::server_io(stream, "kv-login") {
                Ok(io) => io,
                Err(e) => {
                    tracing::warn!(error = %e, "kv-login: udsv3-Schluessel fehlt");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(io);
            let service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
                        match tower::ServiceExt::oneshot(app, req).await {
                            Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                            Err(e) => match e {},
                        }
                    }
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });
    }
}
