//! Z8 Browser-Kern: ECHTER `proxy-kern` + dbnode-Vertraege im WASM-Worker.
//! SQLite+vec als WASM, OPFS (Z8FC1 + StorageBackend), S3/SigV4,
//! postMessage-Fassade mit HTTP-Semantik, AutoLock und Offline-Regel.

pub mod conflict;
pub mod session;
pub mod sigv4;

#[cfg(target_arch = "wasm32")]
mod cipher;
#[cfg(target_arch = "wasm32")]
mod kernel;
#[cfg(target_arch = "wasm32")]
mod opfs;
#[cfg(target_arch = "wasm32")]
mod opfs_backend;
#[cfg(target_arch = "wasm32")]
mod sqlite;

#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;

#[cfg(target_arch = "wasm32")]
use proxy_kern::DbPort;
#[cfg(target_arch = "wasm32")]
use serde_json::{json, Value};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
thread_local! {
    static SESSION: RefCell<session::UiSession> = RefCell::new(session::UiSession::new(0));
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_vec_version() -> Result<String, JsValue> {
    let db = sqlite::Db::open_memory().map_err(err)?;
    db.vec_version().map_err(err)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn sealed_sqlite_fixture(key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let db = sqlite::Db::open_memory().map_err(err)?;
    db.exec("CREATE TABLE kompat (x TEXT)").map_err(err)?;
    db.exec("INSERT INTO kompat VALUES ('wasm-native-gleich')").map_err(err)?;
    let plain = db.serialize().map_err(err)?;
    Ok(cipher::seal(key, &plain))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn open_sealed(key: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsValue> {
    cipher::open(key, sealed).map_err(err)
}

/// Rohes Schreiben/Lesen in OPFS (Tests + native Fixtures).
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn opfs_write_raw(path: &str, bytes: &[u8]) -> Result<usize, JsValue> {
    opfs::write_path_async(path, bytes).await.map_err(err)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn opfs_read_raw(path: &str) -> Option<Vec<u8>> {
    opfs::read_path_async(path).await
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn opfs_list_raw(path: &str) -> Vec<String> {
    opfs::list_path_async(path).await
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn browser_selftest(key: &[u8]) -> Result<String, JsValue> {
    let db = sqlite::Db::open_memory().map_err(err)?;
    let vec = db.vec_version().map_err(err)?;
    db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT)").map_err(err)?;
    db.exec("INSERT INTO t (note) VALUES ('hallo-browser')").map_err(err)?;
    db.exec("CREATE VIRTUAL TABLE v USING vec0(embedding float[4])").map_err(err)?;
    let rows = db.query("SELECT note FROM t").map_err(err)?;
    let plain = db.serialize().map_err(err)?;
    let sealed = cipher::seal(key, &plain);
    let opened = cipher::open(key, &sealed).map_err(err)?;
    assert_eq!(opened, plain, "Cipher-Roundtrip != plain");
    let name = "z8-selftest.db";
    opfs::write_async(name, &sealed).await.map_err(err)?;
    let back = opfs::read_async(name).await.ok_or_else(|| err("OPFS read leer"))?;
    assert_eq!(back, sealed, "OPFS roundtrip != geschrieben");
    let listed = opfs::list_async().await;
    let unsealed = cipher::open(key, &back).map_err(err)?;
    let db2 = sqlite::Db::open_memory().map_err(err)?;
    db2.deserialize(&unsealed).map_err(err)?;
    let rows2 = db2.query("SELECT note FROM t").map_err(err)?;
    assert_eq!(rows, rows2);
    let _ = opfs::delete_async(name).await;
    let persisted = wasm_bindgen_futures::JsFuture::from(opfs::persist())
        .await
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let quota = wasm_bindgen_futures::JsFuture::from(opfs::quota())
        .await
        .ok()
        .and_then(|v| {
            js_sys::Reflect::get(&v, &JsValue::from_str("quota"))
                .ok()
                .and_then(|q| q.as_f64())
        })
        .unwrap_or(0.0);
    Ok(json!({
        "vec_version": vec,
        "rows": rows,
        "plain_bytes": plain.len(),
        "sealed_bytes": sealed.len(),
        "opfs_listed": listed,
        "persisted": persisted,
        "quota": quota,
    })
    .to_string())
}

/// OpfsBackend am gemeinsamen StorageBackend-Trait: echter Roundtrip.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn opfs_backend_selftest() -> Result<String, JsValue> {
    use z8run_core::dbnode_contract_storage::StorageBackend;
    opfs_backend::init().await.map_err(err)?;
    let be = opfs_backend::OpfsBackend;
    let k1 = "cache/k1.bin";
    let k2 = "cache/sub/k2.bin";
    be.write(k1, b"opfs-trait-1").await.map_err(db_err)?;
    be.write(k2, b"opfs-trait-2").await.map_err(db_err)?;
    let r1 = be.read(k1).await.map_err(db_err)?.unwrap_or_default();
    let listed = be.list("cache/").await.map_err(db_err)?;
    assert_eq!(r1, b"opfs-trait-1");
    assert!(listed.iter().any(|k| k == k1), "list ohne {k1}: {listed:?}");
    assert!(listed.iter().any(|k| k == k2), "list ohne {k2}: {listed:?}");
    be.delete(k1).await.map_err(db_err)?;
    assert!(be.read(k1).await.map_err(db_err)?.is_none(), "delete wirkungslos");
    Ok(json!({
        "kind": be.kind(),
        "listed": listed,
        "read": String::from_utf8_lossy(&r1),
    })
    .to_string())
}

#[cfg(target_arch = "wasm32")]
fn db_err(e: z8run_core::dbnode_contract_types::DbError) -> JsValue {
    err(e)
}

/// Versiegelte DB-Datei (Z8FC1) aus OPFS — Beweis der Chiffre-Form.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn db_sealed_dump(db_id: &str) -> Option<Vec<u8>> {
    kernel::dump_db(db_id)
}

/// DB-Key-Ableitung (HKDF wie nativ) fuer den Fixture-Abgleich im Test.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn db_key(master: &[u8], db_id: &str) -> Vec<u8> {
    kernel::derive_db_key(master, db_id).unwrap_or_default().to_vec()
}

/// Kernel-Status (fuer /v1/status und Browser-Tests).
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn kernel_status() -> String {
    kernel::with_kernel(|k| k.status().to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn facade(request_json: &str) -> String {
    let req: Value = serde_json::from_str(request_json).unwrap_or(Value::Null);
    let method = req["method"].as_str().unwrap_or("GET");
    let path = req["path"].as_str().unwrap_or("/");
    let body = &req["body"];
    match (method, path) {
        ("GET", "/v1/status") => {
            let ks = kernel::with_kernel(|k| k.status());
            json!({
                "status": 200,
                "body": {
                    "kern": "z8run-browser",
                    "proxy_kern": ks["kern"],
                    "sqlite": "wasm",
                    "dbnode": ks["dbnode"],
                    "worker": true,
                    "dbs": ks["dbs"],
                }
            })
            .to_string()
        }
        ("GET", "/v1/kernel/status") => {
            json!({"status": 200, "body": kernel::with_kernel(|k| k.status())}).to_string()
        }
        ("POST", "/v1/kernel/login") | ("POST", "/v1/session/login") => {
            kernel_login(body).await
        }
        ("POST", "/v1/session/autolock") => {
            let sec = body["sec"].as_u64().unwrap_or(300);
            SESSION.with(|s| s.borrow_mut().set_autolock(sec));
            json!({"status": 200, "body": {"autolock_sec": sec}}).to_string()
        }
        ("POST", "/v1/session/check") => {
            let now = body["now_ms"].as_u64().unwrap_or(0);
            let locked = SESSION.with(|s| s.borrow_mut().check_lock(now));
            json!({"status": 200, "body": {"locked": locked}}).to_string()
        }
        ("POST", "/v1/token/rotate") => {
            let token = body["token"].as_str().unwrap_or("");
            match kernel::with_kernel(|k| k.tokens.rotate(token)) {
                Ok(g) => json!({
                    "status": 200,
                    "body": {"token": g.token, "expires_at_ms": g.expires_at_ms}
                })
                .to_string(),
                Err(e) => proxy_err(e),
            }
        }
        ("POST", "/v1/token/check") => {
            let token = body["token"].as_str().unwrap_or("");
            match kernel::with_kernel(|k| k.tokens.validate(token)) {
                Ok(sid) => json!({"status": 200, "body": {"session_id": sid}}).to_string(),
                Err(e) => proxy_err(e),
            }
        }
        ("POST", "/v1/db/open") => db_open(body).await,
        ("POST", "/v1/db/close") => {
            let db_id = body["db_id"].as_str().unwrap_or("main");
            match kernel::BrowserDbPort.close_db(db_id).await {
                Ok(v) => json!({"status": 200, "body": v}).to_string(),
                Err(e) => proxy_err(e),
            }
        }
        ("POST", "/v1/db/exec") => db_exec(body).await,
        ("POST", "/v1/db/query") => db_query(body).await,
        ("POST", "/v1/db/status") => {
            let db_id = body["db_id"].as_str();
            match kernel::BrowserDbPort.status(db_id).await {
                Ok(v) => json!({"status": 200, "body": v}).to_string(),
                Err(e) => proxy_err(e),
            }
        }
        ("POST", "/v1/db/schema") => {
            let db_id = body["db_id"].as_str().unwrap_or("main");
            match kernel::BrowserDbPort.schema(db_id).await {
                Ok(v) => json!({"status": 200, "body": v}).to_string(),
                Err(e) => proxy_err(e),
            }
        }
        ("POST", "/v1/session/logout") => {
            let sid = body["session_id"].as_str().unwrap_or("");
            kernel::with_kernel(|k| {
                k.tokens.revoke_session(sid);
                k.sessions.remove(sid);
            });
            json!({"status": 200, "body": {"ok": true}}).to_string()
        }
        ("POST", "/v1/conflict") => {
            let lw = body["local_wal"].as_u64().unwrap_or(0);
            let lh = body["local_hash"].as_str().unwrap_or("");
            let rw = body["remote_wal"].as_u64().unwrap_or(0);
            let rh = body["remote_hash"].as_str().unwrap_or("");
            let r = conflict::resolve(lw, lh, rw, rh);
            json!({"status": 200, "body": {"event": format!("{r:?}"), "resolution": r}}).to_string()
        }
        ("POST", "/v1/s3/probe") => {
            let ok = body["ok"].as_bool().unwrap_or(false);
            let alive = SESSION.with(|s| s.borrow_mut().s3_probe(ok));
            json!({"status": 200, "body": {"alive": alive}}).to_string()
        }
        _ => json!({"status": 404, "body": {"error": "unbekannter Pfad"}}).to_string(),
    }
}

#[cfg(target_arch = "wasm32")]
async fn kernel_login(body: &Value) -> String {
    use base64::Engine as _;
    if let Err(e) = opfs_backend::init().await {
        return json!({"status": 500, "body": {"error": e}}).to_string();
    }
    let master = body["master_b64"]
        .as_str()
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .unwrap_or_default();
    if master.is_empty() {
        return json!({"status": 400, "body": {"error": "master fehlt"}}).to_string();
    }
    let session_id = body["session_id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("s-{}", js_sys::Date::now() as u64));
    let db_id = body["db_id"].as_str().unwrap_or("main").to_string();
    let now = js_sys::Date::now() as u64;
    let grant = kernel::with_kernel(|k| {
        k.login(
            master.clone(),
            session_id.clone(),
            body["addr_space"].as_str().unwrap_or("browser").to_string(),
            body["addr_user"].as_str().unwrap_or("browser").to_string(),
            body["workspace_bucket"].as_str().unwrap_or("").to_string(),
            vec![db_id.clone()],
            now,
        )
    });
    SESSION.with(|s| s.borrow_mut().login(master.clone()));
    let opened = match kernel::open_db(&db_id, &master, &kernel::browser_cluster("browser")).await {
        Ok(st) => serde_json::to_value(st).unwrap_or(Value::Null),
        Err(e) => return proxy_err(e),
    };
    json!({
        "status": 200,
        "body": {
            "ok": true,
            "session_id": grant.session_id,
            "token": grant.token,
            "expires_at_ms": grant.expires_at_ms,
            "db": opened,
        }
    })
    .to_string()
}

#[cfg(target_arch = "wasm32")]
async fn db_open(body: &Value) -> String {
    use base64::Engine as _;
    if let Err(e) = opfs_backend::init().await {
        return json!({"status": 500, "body": {"error": e}}).to_string();
    }
    let db_id = body["db_id"].as_str().unwrap_or("main");
    let session_id = body["session_id"].as_str().unwrap_or("browser");
    let master = if let Some(b64) = body["master_b64"].as_str() {
        base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default()
    } else {
        match kernel::with_kernel(|k| k.session_master_b64(session_id)) {
            Ok(b64) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    };
    if master.is_empty() {
        return json!({"status": 401, "body": {"error": "kein Master (Login fehlt)"}}).to_string();
    }
    let cluster = if body["cluster"].is_null() {
        kernel::browser_cluster("browser")
    } else {
        body["cluster"].clone()
    };
    match kernel::open_db(db_id, &master, &cluster).await {
        Ok(st) => json!({"status": 200, "body": st}).to_string(),
        Err(e) => proxy_err(e),
    }
}

#[cfg(target_arch = "wasm32")]
async fn db_exec(body: &Value) -> String {
    use proxy_kern::DbPort;
    let db_id = body["db_id"].as_str().unwrap_or("main");
    let session_id = body["session_id"].as_str().unwrap_or("browser");
    let sql = body["sql"].as_str().unwrap_or("");
    let params = body["params"].as_array().cloned().unwrap_or_default();
    match kernel::BrowserDbPort.write(db_id, session_id, sql, params).await {
        Ok(v) => json!({"status": 200, "body": {"ok": true, "outcome": v}}).to_string(),
        Err(e) => proxy_err(e),
    }
}

#[cfg(target_arch = "wasm32")]
async fn db_query(body: &Value) -> String {
    use proxy_kern::DbPort;
    let db_id = body["db_id"].as_str().unwrap_or("main");
    let sql = body["sql"].as_str().unwrap_or("");
    let params = body["params"].as_array().cloned().unwrap_or_default();
    match kernel::BrowserDbPort.query(db_id, sql, params, true).await {
        Ok(v) => json!({"status": 200, "body": {"rows": v["rows"], "columns": v["columns"]}}).to_string(),
        Err(e) => proxy_err(e),
    }
}

#[cfg(target_arch = "wasm32")]
fn proxy_err(e: proxy_kern::ProxyError) -> String {
    json!({"status": 400, "body": {"error": e.to_string(), "code": e.code()}}).to_string()
}

#[cfg(target_arch = "wasm32")]
fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}
