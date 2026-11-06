//! Z8 Browser-Kern: ECHTER `proxy-kern` + dbnode-Vertraege im WASM-Worker.
//! SQLite+vec als WASM, OPFS (Z8FC1 + StorageBackend), S3/SigV4,
//! postMessage-Fassade mit HTTP-Semantik, AutoLock und Offline-Regel.

pub mod apps_load;
pub mod conflict;
pub mod session;
pub mod sigv4;

#[cfg(target_arch = "wasm32")]
mod apps;
#[cfg(target_arch = "wasm32")]
mod cipher;
#[cfg(target_arch = "wasm32")]
mod kernel;
#[cfg(target_arch = "wasm32")]
mod hashdatei3;
#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
mod hashdatei3_test;
#[cfg(target_arch = "wasm32")]
mod login;
#[cfg(target_arch = "wasm32")]
#[path = "../../../../../kronvault/tresor-proxy/src/umschlag.rs"]
pub mod umschlag;
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
#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub async fn opfs_write_raw(path: &str, bytes: &[u8]) -> Result<usize, JsValue> {
    opfs::write_path_async(path, bytes).await.map_err(err)
}

#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub async fn opfs_read_raw(path: &str) -> Option<Vec<u8>> {
    opfs::read_path_async(path).await
}

#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
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
#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub fn db_sealed_dump(db_id: &str) -> Option<Vec<u8>> {
    kernel::dump_db(db_id)
}

/// Nur Test-Build: DB-Klartext aus der Z8FC1-Datei (Roundtrip-Beweis).
#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub fn test_db_plain_dump(db_id: &str) -> Option<Vec<u8>> {
    kernel::dump_db_plain(db_id)
}

/// Test-Naht: App-WASM gegen den Browser-wasmi-Host fahren (Trap-Beweis).
#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub fn wasmi_call_bytes(wasm: &[u8], input_json: &str) -> Result<String, JsValue> {
    let input: Value = serde_json::from_str(input_json).map_err(err)?;
    apps::call_bytes(wasm, &input)
        .map(|v| v.to_string())
        .map_err(|e| err(e.to_string()))
}

#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub fn prompt_insert(name: &str, content: &str) {
    kernel::with_kernel(|k| k.prompts.insert(name, content.as_bytes().to_vec()));
}

#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub fn app_names() -> Vec<String> {
    kernel::with_kernel(|k| k.app_names_all())
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
        ("POST", "/v1/login/passbox") => passbox_login(body).await,
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
        ("GET", "/v1/apps") => {
            let sid = match session_of(body) {
                Ok(s) => s,
                Err(e) => return proxy_err(e),
            };
            let names = kernel::with_kernel(|k| k.app_names(&sid));
            json!({"status": 200, "body": {"apps": names, "runtime": "wasmi", "session_id": sid}}).to_string()
        }
        ("POST", "/v1/apps/call") => {
            let sid = match session_of(body) {
                Ok(s) => s,
                Err(e) => return proxy_err(e),
            };
            let name = body["app"].as_str().unwrap_or("");
            let input = if body["input"].is_null() {
                Value::Null
            } else {
                body["input"].clone()
            };
            match kernel::with_kernel(|k| k.call_app(&sid, name, &input)) {
                Ok(v) => json!({"status": 200, "body": {"reply": v, "session_id": sid}}).to_string(),
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
            // HART: Tokens tot, Session+Master zeroize, Apps/Instanzen weg.
            kernel::with_kernel(|k| {
                k.tokens.revoke_session(sid);
                k.sessions.remove(sid);
                k.drop_apps(sid);
            });
            SESSION.with(|s| s.borrow_mut().wipe());
            json!({"status": 200, "body": {"ok": true, "tokens": 0, "master_zeroized": true, "apps": 0}})
                .to_string()
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

/// Session-Aufloesung fuer App-Routen: Token hat Vorrang, sonst
/// explizite session_id (Test/Worker-Route), sonst "test".
#[cfg(target_arch = "wasm32")]
fn session_of(body: &Value) -> Result<String, proxy_kern::ProxyError> {
    if let Some(tok) = body["token"].as_str().filter(|t| !t.is_empty()) {
        return kernel::with_kernel(|k| k.tokens.validate(tok));
    }
    Ok(body["session_id"].as_str().unwrap_or("test").to_string())
}

#[cfg(target_arch = "wasm32")]
fn offline_guard() -> Option<String> {
    let ok = SESSION.with(|s| s.borrow().write_allowed());
    if ok {
        None
    } else {
        Some(json!({"status": 503, "body": {"error": "Kern offline (fail-closed)", "shutdown": true}}).to_string())
    }
}

#[cfg(target_arch = "wasm32")]
fn login_err(e: login::LoginError) -> String {
    let status = match e.code {
        "UNAUTHORIZED" => 401,
        "UNAVAILABLE" => 503,
        _ => 400,
    };
    json!({"status": status, "body": {"error": e.message, "code": e.code}}).to_string()
}

#[cfg(target_arch = "wasm32")]
async fn passbox_login(body: &Value) -> String {
    // Worker ohne OPFS (z.B. Vercel-Node): Login + App-Call laufen weiter,
    // nur DB-Persistenz entfaellt (fail-soft, kein stiller Datenverlust).
    let storage_ok = match opfs_backend::init().await {
        Ok(()) => true,
        Err(_e) => false,
    };
    let space = body["space"].as_str().unwrap_or("");
    let username = body["username"].as_str().unwrap_or("");
    let password = body["password"].as_str().unwrap_or("");
    let hw_pem = body["hw_pem"].as_str().unwrap_or("");
    let v3 = body["schema"].as_str() == Some("Argon2IDHashDatei/3")
        || body["version"].as_u64() == Some(3);
    if space.is_empty() || username.is_empty() || password.is_empty() || hw_pem.is_empty() {
        return json!({"status": 400, "body": {"error": "Login-Felder unvollstaendig"}}).to_string();
    }
    if !v3 {
        return json!({"status": 410, "body": {"error": "alte Hashdatei entfernt — nur /3"}}).to_string();
    }
    let ok = {
        let addr = match hashdatei3::user_addr(space, username) {
            Ok(a) => a,
            Err(e) => return json!({"status": 400, "body": {"error": e}}).to_string(),
        };
        let (b2b, hw) = if !body["s3"].is_null() {
            let b2b = match login::s3_get_bytes(&body["s3"], &format!("b2b/{addr}.txt")).await {
                Ok(b) => b,
                Err(e) => { SESSION.with(|s| { s.borrow_mut().s3_probe(false); }); return login_err(e); }
            };
            let hw = match login::s3_get_bytes(&body["s3"], &format!("workspaces/{addr}/hw-shards.txt")).await {
                Ok(b) => b,
                Err(e) => { SESSION.with(|s| { s.borrow_mut().s3_probe(false); }); return login_err(e); }
            };
            (String::from_utf8_lossy(&b2b).to_string(), String::from_utf8_lossy(&hw).to_string())
        } else {
            // Die Login-UI holt Hashdatei + HW-Shards über die Server-Naht
            // (/login-ui/v1/world, Schlüssel bleiben serverseitig) und reicht
            // sie hier herein. Der eigentliche Schutz bleibt Passwort + lokal
            // geöffnete HW-Box — kein Test-Backdoor.
            match (body["v3_b2b"].as_str(), body["v3_hw"].as_str()) {
                (Some(a), Some(b)) => (a.to_string(), b.to_string()),
                _ => {
                    SESSION.with(|s| { s.borrow_mut().s3_probe(false); });
                    return json!({"status": 503, "body": {"error": "S3 fehlt (fail-closed)", "shutdown": true}}).to_string();
                }
            }
        };
        match hashdatei3::login_v3(
            &b2b,
            &hw,
            space, username, password, hw_pem,
            body["kem_dk_b64"].as_str().unwrap_or(""),
        ) {
            Ok(v) => v,
            Err(e) => return json!({"status": 401, "body": {"error": e, "code": "UNAUTHORIZED"}}).to_string(),
        }
    };
    SESSION.with(|s| {
        s.borrow_mut().login(ok.master.to_vec());
        s.borrow_mut().s3_probe(true);
    });
    let buckets: Vec<String> = ok
        .passbox_payload["buckets"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let db_id = body["db_id"]
        .as_str()
        .map(str::to_string)
        .or_else(|| buckets.first().cloned())
        .unwrap_or_else(|| "demo".to_string());
    let session_id = body["session_id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("s-{}", js_sys::Date::now() as u64));
    let engines_raw = ok.passbox_payload["engines"].clone();
    let decls = match apps_load::parse_engines(&engines_raw) {
        Ok(d) => d,
        Err(e) => return proxy_err(e),
    };
    let auswahl = match apps_load::selection(&decls, body.get("apps")) {
        Ok(a) => a,
        Err(e) => return proxy_err(e),
    };
    let grant = kernel::with_kernel(|k| {
        k.login(
            ok.master.to_vec(),
            session_id.clone(),
            ok.space_addr.clone(),
            ok.username.clone(),
            body["workspace_bucket"].as_str().unwrap_or("").to_string(),
            if buckets.is_empty() { vec![db_id.clone()] } else { buckets.clone() },
            engines_raw.clone(),
            js_sys::Date::now() as u64,
        )
    });
    // APP-LOAD je Auswahl: S3-GET (manifest + app.wasm) -> validieren ->
    // NUR in der Session registrieren. Kein Bundle im Deploy.
    let mut geladen: Vec<String> = Vec::new();
    for decl in &auswahl {
        let s3 = match engine_s3cfg(body, decl) {
            Ok(v) => v,
            Err(e) => {
                kernel::with_kernel(|k| {
                    k.tokens.revoke_session(&grant.session_id);
                    k.sessions.remove(&grant.session_id);
                    k.drop_apps(&grant.session_id);
                });
                return json!({"status": 400, "body": {"error": e, "code": "BAD_REQUEST"}}).to_string();
            }
        };
        let man_raw = match login::s3_get_bytes(&s3, "manifest.json").await {
            Ok(v) => v,
            Err(e) => {
                kernel::with_kernel(|k| k.drop_apps(&grant.session_id));
                return login_err(e);
            }
        };
        let manifest: Value = match serde_json::from_slice(&man_raw) {
            Ok(v) => v,
            Err(e) => {
                kernel::with_kernel(|k| k.drop_apps(&grant.session_id));
                return json!({"status": 400, "body": {"error": format!("manifest.json: {e}")}}).to_string();
            }
        };
        let app_datei = manifest["app"].as_str().unwrap_or("app.wasm").to_string();
        let wasm = match login::s3_get_bytes(&s3, &app_datei).await {
            Ok(v) => v,
            Err(e) => {
                kernel::with_kernel(|k| k.drop_apps(&grant.session_id));
                return login_err(e);
            }
        };
        let (name, version) = match apps_load::validate_bundle(&decl.name, &manifest, &wasm) {
            Ok(v) => v,
            Err(e) => {
                kernel::with_kernel(|k| k.drop_apps(&grant.session_id));
                return proxy_err(e);
            }
        };
        match crate::apps::WasmiApp::load(&name, &version, &wasm) {
            Ok(app) => {
                kernel::with_kernel(|k| k.register_app(&grant.session_id, app));
                geladen.push(name);
            }
            Err(e) => {
                kernel::with_kernel(|k| k.drop_apps(&grant.session_id));
                return proxy_err(e);
            }
        }
    }
    let opened = if storage_ok {
        match kernel::open_db(&db_id, ok.master.as_slice(), &kernel::browser_cluster("browser")).await {
            Ok(st) => serde_json::to_value(st).unwrap_or(Value::Null),
            Err(e) => return proxy_err(e),
        }
    } else {
        Value::Null
    };
    let fp = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(ok.master.as_slice()))
    };
    json!({
        "status": 200,
        "body": {
            "ok": true,
            "session_id": grant.session_id,
            "token": grant.token,
            "expires_at_ms": grant.expires_at_ms,
            "space_addr": ok.space_addr,
            "user_addr": ok.user_addr,
            "master_sha256": fp,
            "apps_loaded": geladen,
            "db": opened,
        }
    })
    .to_string()
}

/// S3-Konfiguration fuer ein Engine-Bundle: Provider-Creds aus dem
/// ro-Profil (`secrets.providers[0]`), Bucket/Prefix aus der Deklaration.
#[cfg(target_arch = "wasm32")]
fn engine_s3cfg(body: &Value, decl: &apps_load::EngineDecl) -> Result<Value, String> {
    if let Some(p) = body["secrets"]["providers"].as_array().and_then(|a| a.first()) {
        let endpoint = p["endpoint"].as_str().unwrap_or("");
        let host = endpoint
            .strip_prefix("https://")
            .or_else(|| endpoint.strip_prefix("http://"))
            .unwrap_or(endpoint)
            .trim_end_matches('/');
        if host.is_empty() {
            return Err("secrets.providers[0].endpoint fehlt".into());
        }
        return Ok(json!({
            "host": host,
            "region": p["region"].as_str().unwrap_or("us-east-1"),
            "access_key": p["access_key"].as_str().unwrap_or(""),
            "secret_key": p["secret_key"].as_str().unwrap_or(""),
            "bucket": decl.bucket,
            "prefix": decl.prefix,
        }));
    }
    let mut s3 = body["s3"].clone();
    if !s3.is_object() {
        return Err("S3-Zugang fehlt (secrets.providers oder s3)".into());
    }
    s3["bucket"] = Value::String(decl.bucket.clone());
    s3["prefix"] = Value::String(decl.prefix.clone());
    Ok(s3)
}

/// Nur Test-Build: Inline-Welt im /3-Format (b2b + hw-shards + v3-Hybrid).
#[cfg(all(target_arch = "wasm32", feature = "test-login"))]
#[wasm_bindgen]
pub fn test_build_world_v3(passwort: &str, space: &str, username: &str) -> String {
    hashdatei3_test::build_test_world_v3(passwort, space, username).to_string()
}

/// Öffnet den HW-Shard lokal (Faktor 2) für die native WebAuthn-Ceremony.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn open_shard_v3(
    hw_shards: &str,
    hw_pem: &str,
    kem_dk_b64: &str,
) -> Result<String, JsValue> {
    hashdatei3::open_shard_v3(hw_shards, hw_pem, kem_dk_b64)
        .map(|v| v.to_string())
        .map_err(err)
}

#[cfg(target_arch = "wasm32")]
async fn db_open(body: &Value) -> String {
    if let Some(r) = offline_guard() { return r; }
    if let Err(e) = opfs_backend::init().await {
        return json!({"status": 500, "body": {"error": e}}).to_string();
    }
    let db_id = body["db_id"].as_str().unwrap_or("main");
    let session_id = body["session_id"].as_str().unwrap_or("browser");
    let master = match kernel::with_kernel(|k| k.session_master(session_id)) {
        Ok(m) => m,
        Err(_) => Vec::new(),
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
    if let Some(r) = offline_guard() { return r; }
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
    if let Some(r) = offline_guard() { return r; }
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
    json!({"status": e.status(), "body": {"error": e.to_string(), "code": e.code()}}).to_string()
}

#[cfg(target_arch = "wasm32")]
fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}
