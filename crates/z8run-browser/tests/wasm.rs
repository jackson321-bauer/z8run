#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn kern_im_worker_opfs_und_fassade() {
    let key = [7u8; 32];
    let out = z8run_browser::browser_selftest(&key).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let vec = v["vec_version"].as_str().unwrap();
    assert!(vec.starts_with('v'), "vec_version fehlt: {vec}");
    assert_eq!(v["rows"][0][0], "hallo-browser");
    assert!(v["opfs_listed"].as_array().is_some());
    assert!(v["quota"].as_f64().unwrap_or(0.0) > 0.0, "Quota nicht abfragbar: {out}");
    assert!(v["persisted"].is_boolean(), "persist() fehlt: {out}");
    println!("WASM_SELFTEST {out}");

    // S2: ECHTER Kern (proxy-kern) + dbnode im Worker-Status.
    let status = z8run_browser::kernel_status();
    let st: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(st["kern"], "proxy-kern", "Kern nicht aktiv: {status}");
    assert_eq!(st["dbnode"], "wasm-vfs+z8fc1", "dbnode nicht aktiv: {status}");
    let r = z8run_browser::facade(r#"{"method":"GET","path":"/v1/status"}"#).await;
    assert!(r.contains("\"status\":200"), "{r}");
    assert!(r.contains("proxy-kern"), "Kern fehlt in /v1/status: {r}");
    println!("KERN_STATUS {status}");

    // S2/S4: Fassade spricht Kern-API ueber den ECHTEN /3-Login
    // (Test-Welt inline, nur Feature `test-login`; kein Direkt-Master).
    let world: serde_json::Value =
        serde_json::from_str(&z8run_browser::test_build_world_v3(
            "pw-test", "space-test", "kreuz",
        ))
        .unwrap();
    let mut login_body = serde_json::json!({
        "schema": "Argon2IDHashDatei/3",
        "space": "space-test",
        "username": "kreuz",
        "password": "pw-test",
        "hw_pem": world["hw_pem"],
        "v3_b2b": world["v3_b2b"],
        "v3_hw": world["v3_hw"],
        "kem_dk_b64": world["kem_dk_b64"],
        "session_id": "s2",
        "db_id": "kdb"
    });
    let login = serde_json::json!({
        "method": "POST",
        "path": "/v1/login/passbox",
        "body": login_body
    })
    .to_string();
    let r = z8run_browser::facade(&login).await;
    assert!(r.contains("\"status\":200"), "Passbox-Login: {r}");
    assert!(r.contains("\"token\":"), "Token fehlt: {r}");
    assert!(r.contains("\"adapter\":\"opfs\""), "DB-Status im Login fehlt: {r}");
    println!("PASSBOX_LOGIN {r}");

    // S4: falsches Passwort = klare Abweisung (kein Token).
    login_body["password"] = serde_json::json!("falsch");
    let r = z8run_browser::facade(
        &serde_json::json!({"method": "POST", "path": "/v1/login/passbox", "body": login_body})
            .to_string(),
    )
    .await;
    assert!(r.contains("\"status\":401"), "falsches Passwort nicht 401: {r}");
    assert!(r.contains("Passwort falsch"), "keine klare Abweisung: {r}");
    assert!(!r.contains("\"token\":"), "Token trotz falschem Passwort: {r}");
    println!("WRONG_PASSWORD {r}");

    // S4: Hashdatei wird NIE lokal (OPFS) gespeichert.
    let files = z8run_browser::opfs_list_raw("").await;
    assert!(
        !files.iter().any(|f| f.contains("HashDatei") || f.contains("hashdatei")),
        "Hashdatei im OPFS-Cache: {files:?}"
    );
    println!("OPFS_OHNE_HASHDATEI {files:?}");

    let exec = serde_json::json!({
        "method": "POST",
        "path": "/v1/db/exec",
        "body": {"db_id": "kdb", "session_id": "s2", "sql": "CREATE TABLE k (x TEXT)"}
    })
    .to_string();
    let r = z8run_browser::facade(&exec).await;
    assert!(r.contains("\"status\":200"), "Kern exec: {r}");
    let ins = serde_json::json!({
        "method": "POST",
        "path": "/v1/db/exec",
        "body": {"db_id": "kdb", "session_id": "s2", "sql": "INSERT INTO k VALUES ('kern-ok')"}
    })
    .to_string();
    assert!(z8run_browser::facade(&ins).await.contains("\"status\":200"));
    let q = serde_json::json!({
        "method": "POST",
        "path": "/v1/db/query",
        "body": {"db_id": "kdb", "sql": "SELECT x FROM k"}
    })
    .to_string();
    let r = z8run_browser::facade(&q).await;
    assert!(r.contains("kern-ok"), "Kern query: {r}");

    // S2: DB-Datei in OPFS = Z8FC1-Chiffre (Worker-Side-Dump).
    let sealed = z8run_browser::db_sealed_dump("kdb").expect("kein DB-Dump");
    assert_eq!(&sealed[..5], b"Z8FC1", "DB-Datei ist keine Z8FC1-Chiffre");
    assert!(
        !sealed.windows(15).any(|w| w == b"SQLite format 3"),
        "Klartext-SQLite in OPFS"
    );
    let plain = z8run_browser::test_db_plain_dump("kdb").expect("DB nicht entsiegelbar");
    assert!(plain.starts_with(b"SQLite format 3"));
    println!("DB_Z8FC1 bytes={} plain={}", sealed.len(), plain.len());

    // S2: OpfsBackend am gemeinsamen StorageBackend-Trait (Roundtrip).
    let r = z8run_browser::opfs_backend_selftest().await.unwrap();
    assert!(r.contains("\"kind\":\"opfs\""), "Trait-Adapter: {r}");
    assert!(r.contains("opfs-trait-1"), "Trait-Read: {r}");
    println!("OPFS_TRAIT {r}");

    // S2: nativ erzeugte Z8FC1-Datei in OPFS lesen (Kompatibilitaet).
    let native = include_bytes!("fixtures/native-db.z8fc");
    z8run_browser::opfs_write_raw("z8db/native/native.z8fc", native)
        .await
        .unwrap();
    let back = z8run_browser::opfs_read_raw("z8db/native/native.z8fc")
        .await
        .expect("OPFS read leer");
    assert_eq!(back, native);
    let plain = z8run_browser::open_sealed(&[9u8; 32], &back).unwrap();
    assert!(plain.starts_with(b"SQLite format 3"), "native Fixture nicht lesbar");
    assert!(plain.windows(b"native-nach-wasm".len()).any(|w| w == b"native-nach-wasm"));
    println!("NATIVE_TO_WASM_OK bytes={}", plain.len());

    // S3: wasmi-Apps im Worker (echo.wasm unveraendert, SHA-Signatur).
    let names = z8run_browser::app_names();
    assert!(names.iter().any(|n| n == "echo"), "echo fehlt: {names:?}");
    let input = serde_json::json!({"op": "echo", "input": {"text": "hallo-wasmi"}});
    let payload = serde_json::to_string(&input).unwrap();
    let expected = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(payload.as_bytes()))
    };
    let call = serde_json::json!({
        "method": "POST",
        "path": "/v1/apps/call",
        "body": {"app": "echo", "input": input}
    })
    .to_string();
    let r = z8run_browser::facade(&call).await;
    assert!(r.contains("\"status\":200"), "App-Call: {r}");
    let rv: serde_json::Value = serde_json::from_str(&r).unwrap();
    let reply = &rv["body"]["reply"];
    assert_eq!(reply["signature"].as_str().unwrap_or(""), expected, "SHA-Signatur falsch: {r}");
    assert_eq!(reply["app"], "echo");
    assert_eq!(reply["echo"], input, "Echo != Input");
    println!("WASMI_ECHO {r}");

    // Prompt-Store-Regel: App-Antwort NIE mit Prompt-Inhalt.
    z8run_browser::prompt_insert("sys", "PROMPT-GEHEIM-XYZ");
    let r = z8run_browser::facade(&call).await;
    assert!(!r.contains("PROMPT-GEHEIM-XYZ"), "Prompt im App-Ergebnis: {r}");

    // App mit fs/net-Import: Trap bei Instanziierung (Sandbox wie nativ).
    let trap = r#"(module
        (import "env" "fs_read" (func $fs (param i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "z8_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "z8_process") (param i32 i32) (result i32)
            i32.const 0 call $fs drop i32.const -1))"#;
    let wasm = wat::parse_str(trap).unwrap();
    let err = z8run_browser::wasmi_call_bytes(&wasm, "{}").unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Import") || msg.contains("instantiate"),
        "Import-App nicht getrappt: {msg}"
    );
    println!("WASMI_TRAP {msg}");

    // AutoLock via Fassade (Default 300, dann 1 s im Test).
    z8run_browser::facade(r#"{"method":"POST","path":"/v1/session/check","body":{"now_ms":1000}}"#).await;
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/session/autolock","body":{"sec":1}}"#,
    )
    .await;
    assert!(r.contains("\"autolock_sec\":1"), "{r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/session/check","body":{"now_ms":2500}}"#,
    )
    .await;
    assert!(r.contains("\"locked\":true"), "{r}");

    // Konflikt: aelterer OPFS-Stand + neuere S3-WAL => Replay + UI-Event.
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/conflict","body":{"local_wal":7,"local_hash":"aa","remote_wal":9,"remote_hash":"bb"}}"#,
    )
    .await;
    assert!(r.contains("ReplayRemote"), "Konflikt-Event fehlt: {r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/conflict","body":{"local_wal":9,"local_hash":"aa","remote_wal":9,"remote_hash":"bb"}}"#,
    )
    .await;
    assert!(r.contains("ChainMismatch"), "Kettenkonflikt fehlt: {r}");

    // Offline-Regel: S3-Kontakt fehlt => SHUTDOWN.
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/s3/probe","body":{"ok":false}}"#,
    )
    .await;
    assert!(r.contains("\"alive\":false"), "{r}");

    // S4: Login ohne S3 = fail-closed (Shutdown).
    let no_s3 = serde_json::json!({
        "method": "POST",
        "path": "/v1/login/passbox",
        "body": {
            "schema": "Argon2IDHashDatei/3",
            "space": "space-test", "username": "kreuz", "password": "pw-test",
            "hw_pem": world["hw_pem"]
        }
    })
    .to_string();
    let r = z8run_browser::facade(&no_s3).await;
    assert!(r.contains("\"status\":503"), "kein fail-closed: {r}");
    assert!(r.contains("\"shutdown\":true"), "kein Shutdown: {r}");
    println!("NO_S3_FAILCLOSED {r}");
    let blocked = serde_json::json!({
        "method": "POST",
        "path": "/v1/db/exec",
        "body": {"db_id": "kdb", "session_id": "s2", "sql": "INSERT INTO k VALUES ('darf-nicht')"}
    })
    .to_string();
    let r = z8run_browser::facade(&blocked).await;
    assert!(r.contains("\"status\":503"), "Shutdown blockiert Schreiben nicht: {r}");
    assert!(r.contains("fail-closed"), "kein fail-closed-Grund: {r}");
    println!("SHUTDOWN_BLOCK {r}");
}
