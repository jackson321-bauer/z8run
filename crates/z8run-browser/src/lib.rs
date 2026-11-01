//! Z8 Browser-Kern: SQLite+vec als WASM, OPFS, Z8FC1-Huelle, S3/SigV4,
//! postMessage-Fassade mit HTTP-Semantik, AutoLock und Offline-Regel.

pub mod session;
pub mod sigv4;

#[cfg(target_arch = "wasm32")]
mod cipher;
#[cfg(target_arch = "wasm32")]
mod opfs;
#[cfg(target_arch = "wasm32")]
mod sqlite;

#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;

#[cfg(target_arch = "wasm32")]
use serde_json::{json, Value};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
thread_local! {
    static DB: RefCell<Option<sqlite::Db>> = const { RefCell::new(None) };
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
    let quota = wasm_bindgen_futures::JsFuture::from(opfs::quota()).await.ok();
    Ok(json!({
        "vec_version": vec,
        "rows": rows,
        "plain_bytes": plain.len(),
        "sealed_bytes": sealed.len(),
        "opfs_listed": listed,
        "persisted": persisted,
        "quota": quota.map(|q| q.as_f64().unwrap_or(0.0)).unwrap_or(0.0),
    })
    .to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn facade(request_json: &str) -> String {
    let req: Value = serde_json::from_str(request_json).unwrap_or(Value::Null);
    let method = req["method"].as_str().unwrap_or("GET");
    let path = req["path"].as_str().unwrap_or("/");
    match (method, path) {
        ("GET", "/v1/status") => json!({
            "status": 200,
            "body": {"kern": "z8run-browser", "sqlite": "wasm", "worker": true}
        })
        .to_string(),
        ("POST", "/v1/db/exec") => {
            let sql = req["body"]["sql"].as_str().unwrap_or("");
            with_db(|db| match db.exec(sql) {
                Ok(()) => json!({"status": 200, "body": {"ok": true}}),
                Err(e) => json!({"status": 400, "body": {"error": e}}),
            })
        }
        ("POST", "/v1/db/query") => {
            let sql = req["body"]["sql"].as_str().unwrap_or("");
            with_db(|db| match db.query(sql) {
                Ok(rows) => json!({"status": 200, "body": {"rows": rows}}),
                Err(e) => json!({"status": 400, "body": {"error": e}}),
            })
        }
        ("POST", "/v1/session/login") => {
            let master = req["body"]["master_b64"]
                .as_str()
                .and_then(|b| base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    b,
                ).ok())
                .unwrap_or_default();
            SESSION.with(|s| s.borrow_mut().login(master));
            json!({"status": 200, "body": {"ok": true}}).to_string()
        }
        ("POST", "/v1/session/autolock") => {
            let sec = req["body"]["sec"].as_u64().unwrap_or(300);
            SESSION.with(|s| s.borrow_mut().set_autolock(sec));
            json!({"status": 200, "body": {"autolock_sec": sec}}).to_string()
        }
        ("POST", "/v1/session/check") => {
            let now = req["body"]["now_ms"].as_u64().unwrap_or(0);
            let locked = SESSION.with(|s| s.borrow_mut().check_lock(now));
            json!({"status": 200, "body": {"locked": locked}}).to_string()
        }
        ("POST", "/v1/s3/probe") => {
            let ok = req["body"]["ok"].as_bool().unwrap_or(false);
            let alive = SESSION.with(|s| s.borrow_mut().s3_probe(ok));
            json!({"status": 200, "body": {"alive": alive}}).to_string()
        }
        _ => json!({"status": 404, "body": {"error": "unbekannter Pfad"}}).to_string(),
    }
}

#[cfg(target_arch = "wasm32")]
fn with_db(f: impl FnOnce(&sqlite::Db) -> Value) -> String {
    DB.with(|cell| {
        if cell.borrow().is_none() {
            match sqlite::Db::open_memory() {
                Ok(db) => *cell.borrow_mut() = Some(db),
                Err(e) => return json!({"status": 500, "body": {"error": e}}).to_string(),
            }
        }
        let borrow = cell.borrow();
        f(borrow.as_ref().expect("gerade geoeffnet")).to_string()
    })
}

#[cfg(target_arch = "wasm32")]
fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}
