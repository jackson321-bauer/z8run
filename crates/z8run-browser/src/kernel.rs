//! ECHTER Proxy-Kern im Browser-Worker.
//!
//! Kompiliert derselbe `proxy-kern` wie nativ (Tokens, Sessions, Apps,
//! Prompt-Store). Nur die Ports sind Browser-Adapter: `BrowserDbPort`
//! spricht SQLite+vec im WASM und legt die DB als Z8FC1 in OPFS ab.

use std::cell::RefCell;
use std::collections::HashMap;

use async_trait::async_trait;
use hkdf::Hkdf;
use proxy_kern::{
    Clock, DbPort, PromptStore, ProxyError, Random, SessionState, SessionStore, TokenConfig,
    TokenGrant, TokenManager,
};
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;
use z8run_core::dbnode_contract_types::{
    DbStatus, QueryOutcome, SchemaInfo, TableSchema, WriteOutcome,
};

use crate::apps::WasmiApp;
use crate::cipher;
use crate::opfs_backend;
use crate::sqlite;

const DEFAULT_CLUSTER: &str = "browser";
const DB_SUFFIX: &str = "db.sqlite";

pub struct BrowserClock;
impl Clock for BrowserClock {
    fn now_ms(&self) -> u64 {
        js_sys::Date::now() as u64
    }
}

pub struct BrowserRandom;
impl Random for BrowserRandom {
    fn fill(&self, buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }
}

pub struct BrowserDb {
    db: sqlite::Db,
    key: [u8; 32],
    db_id: String,
    cluster_id: String,
    path: String,
    reserved_by: Option<String>,
    wal_nr: u64,
    writable: bool,
}

impl BrowserDb {
    fn status(&self) -> DbStatus {
        DbStatus {
            db_id: self.db_id.clone(),
            cluster_id: self.cluster_id.clone(),
            adapter: "opfs".into(),
            local_path: self.path.clone(),
            reservation: if self.reserved_by.is_some() {
                "reserviert".into()
            } else {
                "frei".into()
            },
            reserved_by: self.reserved_by.clone(),
            wal_stand: self.wal_nr,
            wal_synced: self.wal_nr,
            wal_pending: 0,
            snapshots: 0,
            remote_wal_downloaded: 0,
            restored_from_snapshot: false,
        }
    }
}

pub struct Kernel {
    pub sessions: SessionStore,
    pub tokens: Arc<TokenManager>,
    pub prompts: PromptStore,
    pub dbs: RefCell<HashMap<String, BrowserDb>>,
    /// Apps je SESSION: `session_id -> (app_name -> Instanz)`. Apps
    /// verschiedener Logins sehen sich NIE; Logout entfernt den Eintrag.
    pub apps: RefCell<HashMap<String, HashMap<String, WasmiApp>>>,
    /// S3-Provider je SESSION (nur RAM; Platzhalter-Aufloesung fuer Egress).
    pub providers: RefCell<HashMap<String, Value>>,
    /// kv-store-wasm als Hilfsmodul IM Isolat (Bytes aus dem Deploy).
    pub kv_wasm: RefCell<Option<Vec<u8>>>,
    /// In-Isolat-Heft: Events, die sonst an einen Daemon gingen.
    pub heft: RefCell<Vec<Value>>,
}

impl Kernel {
    pub fn new() -> Self {
        let mut apps: HashMap<String, HashMap<String, WasmiApp>> = HashMap::new();
        // TEST-ONLY: Echo-App fuer die Wasmi-Selbsttests. Im DEPLOY ist das
        // Feature aus -> KEINE vorinstallierte App im Worker.
        #[cfg(feature = "test-login")]
        {
            let echo = WasmiApp::load(
                "echo",
                "0.1.0",
                include_bytes!("../../../apps/echo/echo.wasm"),
            );
            if let Ok(app) = echo {
                let mut m = HashMap::new();
                m.insert("echo".to_string(), app);
                apps.insert("test".to_string(), m);
            }
        }
        Self {
            sessions: SessionStore::new(),
            tokens: Arc::new(TokenManager::new(
                TokenConfig::default(),
                Arc::new(BrowserClock),
                Arc::new(BrowserRandom),
            )),
            prompts: PromptStore::new(),
            dbs: RefCell::new(HashMap::new()),
            apps: RefCell::new(apps),
            providers: RefCell::new(HashMap::new()),
            kv_wasm: RefCell::new(None),
            heft: RefCell::new(Vec::new()),
        }
    }

    pub fn set_providers(&self, session_id: &str, providers: Value) {
        self.providers
            .borrow_mut()
            .insert(session_id.to_string(), providers);
    }

    pub fn providers_von(&self, session_id: &str) -> Option<Value> {
        self.providers.borrow().get(session_id).cloned()
    }

    pub fn set_kv_wasm(&self, bytes: Vec<u8>) {
        *self.kv_wasm.borrow_mut() = Some(bytes);
    }

    pub fn kv_bytes(&self) -> Option<Vec<u8>> {
        self.kv_wasm.borrow().clone()
    }

    pub fn heft_push(&self, ev: Value) {
        self.heft.borrow_mut().push(ev);
    }

    pub fn heft_events(&self) -> Vec<Value> {
        self.heft.borrow().clone()
    }

    pub fn status(&self) -> Value {
        let dbs: Vec<String> = self.dbs.borrow().keys().cloned().collect();
        let apps_gesamt: usize = self.apps.borrow().values().map(HashMap::len).sum();
        let sessions_mit_apps = self.apps.borrow().values().filter(|m| !m.is_empty()).count();
        json!({
            "kern": "proxy-kern",
            "kern_version": env!("CARGO_PKG_VERSION"),
            "dbnode": "wasm-vfs+z8fc1",
            "worker": true,
            "sessions": self.sessions.count(),
            "tokens": self.tokens.active_count(),
            "prompts": self.prompts.names().len(),
            "dbs": dbs,
            "apps": apps_gesamt,
            "sessions_mit_apps": sessions_mit_apps,
        })
    }

    /// App-Namen aller Sessions (nur Statusanzeige).
    pub fn app_names_all(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .apps
            .borrow()
            .values()
            .flat_map(|m| m.keys().cloned())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// App-Namen GENAU dieser Session.
    pub fn app_names(&self, session_id: &str) -> Vec<String> {
        let apps = self.apps.borrow();
        let Some(map) = apps.get(session_id) else {
            return Vec::new();
        };
        let mut v: Vec<String> = map.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn app_infos(&self, session_id: &str) -> Vec<proxy_kern::AppInfo> {
        let apps = self.apps.borrow();
        let Some(map) = apps.get(session_id) else {
            return Vec::new();
        };
        let mut v: Vec<proxy_kern::AppInfo> = map.values().map(WasmiApp::info).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Registriert eine App NUR fuer eine Session (RAM-only).
    pub fn register_app(&self, session_id: &str, app: WasmiApp) {
        self.apps
            .borrow_mut()
            .entry(session_id.to_string())
            .or_default()
            .insert(app.name.clone(), app);
    }

    /// Logout/Expiry: Instanz+WASM-Speicher der Session fallen lassen.
    pub fn drop_apps(&self, session_id: &str) {
        self.apps.borrow_mut().remove(session_id);
        self.providers.borrow_mut().remove(session_id);
    }

    pub fn call_app(
        &self,
        session_id: &str,
        name: &str,
        input: &Value,
    ) -> Result<Value, ProxyError> {
        let apps = self.apps.borrow();
        let map = apps
            .get(session_id)
            .ok_or_else(|| ProxyError::Unauthorized)?;
        let app = map
            .get(name)
            .ok_or_else(|| ProxyError::NotFound(format!("app {name}")))?;
        Ok(app.call(input)?.payload)
    }

    pub fn login(
        &self,
        master: Vec<u8>,
        session_id: String,
        addr_space: String,
        addr_user: String,
        bucket: String,
        dbs: Vec<String>,
        engines: Value,
        now_ms: u64,
    ) -> TokenGrant {
        self.sessions.insert(SessionState::new(
            session_id.clone(),
            addr_space,
            addr_user,
            bucket,
            engines,
            dbs,
            master,
            now_ms,
        ));
        self.tokens.issue(&session_id)
    }

    pub fn session_master(&self, session_id: &str) -> Result<Vec<u8>, ProxyError> {
        self.sessions
            .with(session_id, |s| s.master_bytes().to_vec())
            .ok_or(ProxyError::Unauthorized)
    }
}

thread_local! {
    pub static KERNEL: RefCell<Kernel> = RefCell::new(Kernel::new());
}

pub fn with_kernel<R>(f: impl FnOnce(&mut Kernel) -> R) -> R {
    KERNEL.with(|k| f(&mut k.borrow_mut()))
}

/// DB-Key wie nativ: HKDF-SHA256(master, salt `z8-dbbox-db-key-v1`, info=db_id).
pub fn derive_db_key(master: &[u8], db_id: &str) -> Result<[u8; 32], String> {
    if master.is_empty() {
        return Err("Masterkey fehlt".into());
    }
    let hk = Hkdf::<Sha256>::new(Some(b"z8-dbbox-db-key-v1"), master);
    let mut out = [0u8; 32];
    hk.expand(db_id.as_bytes(), &mut out)
        .map_err(|_| "HKDF expand fehlgeschlagen".to_string())?;
    Ok(out)
}

fn db_path(cluster_id: &str, db_id: &str) -> String {
    let safe = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect()
    };
    format!("z8db/{}/{}/{}", safe(cluster_id), safe(db_id), DB_SUFFIX)
}

fn cluster_from_value(v: &Value) -> (String, String) {
    let cluster_id = v["cluster_id"].as_str().unwrap_or(DEFAULT_CLUSTER).to_string();
    let root = v["local_dir"].as_str().unwrap_or("opfs").to_string();
    (cluster_id, root)
}

/// Oeffnet eine DB aus OPFS (Z8FC1) oder neu im RAM und haengt sie ein.
pub async fn open_db(
    db_id: &str,
    master: &[u8],
    cluster: &Value,
) -> Result<DbStatus, ProxyError> {
    let (cluster_id, _root) = cluster_from_value(cluster);
    if let Some(st) = with_kernel(|k| k.dbs.borrow().get(db_id).map(BrowserDb::status)) {
        return Ok(st);
    }
    let key = derive_db_key(master, db_id).map_err(ProxyError::Db)?;
    let path = db_path(&cluster_id, db_id);
    let db = sqlite::Db::open_memory().map_err(ProxyError::Db)?;
    if let Some(sealed) = opfs_backend::get_sync(&path).map_err(|e| ProxyError::Db(e.to_string()))? {
        let plain = cipher::open(&key, &sealed).map_err(ProxyError::Db)?;
        db.deserialize(&plain).map_err(ProxyError::Db)?;
    }
    db.exec("CREATE TABLE IF NOT EXISTS _z8_line_epochs (nr INTEGER PRIMARY KEY, hash TEXT NOT NULL)")
        .map_err(ProxyError::Db)?;
    let handle = BrowserDb {
        db,
        key,
        db_id: db_id.to_string(),
        cluster_id,
        path,
        reserved_by: None,
        wal_nr: 0,
        writable: true,
    };
    let st = handle.status();
    with_kernel(|k| k.dbs.borrow_mut().insert(db_id.to_string(), handle));
    Ok(st)
}

/// SQLite-Stand als Z8FC1 in den OPFS-Container schreiben (Worker-Side).
/// Synchron (SyncAccessHandle), damit die DbPort-Send-Futures kein JsFuture
/// ueber eine Thread-Grenze tragen.
pub fn persist_db(db_id: &str) -> Result<(), ProxyError> {
    let job = with_kernel(|k| {
        let dbs = k.dbs.borrow();
        let d = dbs.get(db_id).ok_or_else(|| ProxyError::NotFound(db_id.into()))?;
        let plain = d.db.serialize().map_err(ProxyError::Db)?;
        Ok::<_, ProxyError>((d.path.clone(), cipher::seal(&d.key, &plain)))
    })?;
    opfs_backend::put_sync(&job.0, &job.1).map_err(|e| ProxyError::Db(e.to_string()))
}

pub struct BrowserDbPort;

#[async_trait]
impl DbPort for BrowserDbPort {
    async fn open_db(
        &self,
        db_id: &str,
        master_key_reg: &str,
        cluster: Value,
    ) -> Result<Value, ProxyError> {
        use base64::Engine as _;
        let master = base64::engine::general_purpose::STANDARD
            .decode(master_key_reg)
            .map_err(|e| ProxyError::BadRequest(format!("master-key: {e}")))?;
        let st = open_db(db_id, &master, &cluster).await?;
        serde_json::to_value(st).map_err(|e| ProxyError::Internal(e.to_string()))
    }

    async fn close_db(&self, db_id: &str) -> Result<Value, ProxyError> {
        let removed = with_kernel(|k| k.dbs.borrow_mut().remove(db_id));
        removed
            .map(|d| json!({"closed": d.db_id}))
            .ok_or_else(|| ProxyError::NotFound(db_id.into()))
    }

    async fn reserve(&self, db_id: &str, session_id: &str) -> Result<Value, ProxyError> {
        with_kernel(|k| {
            let mut dbs = k.dbs.borrow_mut();
            let d = dbs.get_mut(db_id).ok_or_else(|| ProxyError::NotFound(db_id.into()))?;
            if let Some(owner) = &d.reserved_by {
                if owner != session_id {
                    return Err(ProxyError::Db("DB ist bereits reserviert".into()));
                }
            }
            d.reserved_by = Some(session_id.to_string());
            Ok(json!({"reserved": db_id}))
        })
    }

    async fn release(&self, db_id: &str, session_id: &str) -> Result<Value, ProxyError> {
        with_kernel(|k| {
            let mut dbs = k.dbs.borrow_mut();
            let d = dbs.get_mut(db_id).ok_or_else(|| ProxyError::NotFound(db_id.into()))?;
            if d.reserved_by.as_deref() != Some(session_id) {
                return Err(ProxyError::Db("Reservierung gehoert anderer Session".into()));
            }
            d.reserved_by = None;
            Ok(json!({"released": db_id}))
        })
    }

    async fn query(
        &self,
        db_id: &str,
        sql: &str,
        params: Vec<Value>,
        readonly: bool,
    ) -> Result<Value, ProxyError> {
        let _ = readonly;
        with_kernel(|k| {
            let dbs = k.dbs.borrow();
            let d = dbs.get(db_id).ok_or_else(|| ProxyError::NotFound(db_id.into()))?;
            let (columns, rows) = d.db.query_params(sql, &params).map_err(ProxyError::Db)?;
            let out = QueryOutcome { columns, rows, rows_affected: 0 };
            serde_json::to_value(out).map_err(|e| ProxyError::Internal(e.to_string()))
        })
    }

    async fn write(
        &self,
        db_id: &str,
        session_id: &str,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Value, ProxyError> {
        let wal = with_kernel(|k| {
            let mut dbs = k.dbs.borrow_mut();
            let d = dbs.get_mut(db_id).ok_or_else(|| ProxyError::NotFound(db_id.into()))?;
            if !d.writable {
                return Err(ProxyError::Db("DB ist nicht schreibbar".into()));
            }
            if let Some(owner) = &d.reserved_by {
                if owner != session_id {
                    return Err(ProxyError::Db("Schreiben ohne Reservierung".into()));
                }
            }
            let rows_affected = d.db.exec_params(sql, &params).map_err(ProxyError::Db)?;
            d.wal_nr += 1;
            let out = WriteOutcome { rows_affected, wal_nr: d.wal_nr };
            Ok::<_, ProxyError>(out)
        })?;
        persist_db(db_id)?;
        serde_json::to_value(wal).map_err(|e| ProxyError::Internal(e.to_string()))
    }

    async fn status(&self, db_id: Option<&str>) -> Result<Value, ProxyError> {
        with_kernel(|k| {
            let dbs = k.dbs.borrow();
            match db_id {
                Some(id) => {
                    let d = dbs.get(id).ok_or_else(|| ProxyError::NotFound(id.into()))?;
                    serde_json::to_value(vec![d.status()]).map_err(|e| ProxyError::Internal(e.to_string()))
                }
                None => {
                    let v: Vec<DbStatus> = dbs.values().map(BrowserDb::status).collect();
                    serde_json::to_value(v).map_err(|e| ProxyError::Internal(e.to_string()))
                }
            }
        })
    }

    async fn schema(&self, db_id: &str) -> Result<Value, ProxyError> {
        with_kernel(|k| {
            let dbs = k.dbs.borrow();
            let d = dbs.get(db_id).ok_or_else(|| ProxyError::NotFound(db_id.into()))?;
            let (_cols, rows) = d
                .db
                .query_params(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                    &[],
                )
                .map_err(ProxyError::Db)?;
            let tables: Vec<TableSchema> = rows
                .iter()
                .filter_map(|r| r.first().and_then(Value::as_str))
                .map(|name| TableSchema {
                    name: name.to_string(),
                    columns: Vec::new(),
                    rows: 0,
                    wal_stand: 0,
                    reserved_by: None,
                })
                .collect();
            let info = SchemaInfo { db_id: db_id.to_string(), tables };
            serde_json::to_value(info).map_err(|e| ProxyError::Internal(e.to_string()))
        })
    }
}

/// Versiegelte DB-Datei aus dem OPFS-Container (Worker-Side-Dump fuer Tests).
#[cfg(feature = "test-login")]
pub fn dump_db(db_id: &str) -> Option<Vec<u8>> {
    with_kernel(|k| {
        let dbs = k.dbs.borrow();
        let d = dbs.get(db_id)?;
        opfs_backend::get_sync(&d.path).ok().flatten()
    })
}

/// Nur Test: versiegelte DB oeffnen (beweist Z8FC1->SQLite-Roundtrip).
#[cfg(feature = "test-login")]
pub fn dump_db_plain(db_id: &str) -> Option<Vec<u8>> {
    with_kernel(|k| {
        let dbs = k.dbs.borrow();
        let d = dbs.get(db_id)?;
        let sealed = opfs_backend::get_sync(&d.path).ok().flatten()?;
        cipher::open(&d.key, &sealed).ok()
    })
}

/// Cluster-/Default-Konfiguration fuer den Browser (OPFS-Adapter).
pub fn browser_cluster(cluster_id: &str) -> Value {
    json!({"cluster_id": cluster_id, "local_dir": "opfs", "adapter": {"Fs": {"root": "opfs"}}})
}
