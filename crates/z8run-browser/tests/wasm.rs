#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn vec_opfs_cipher_und_fassade() {
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

    // Fassade mit HTTP-Semantik (Worker postMessage).
    let r = z8run_browser::facade(r#"{"method":"GET","path":"/v1/status"}"#);
    assert!(r.contains("\"status\":200"), "{r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/db/exec","body":{"sql":"CREATE TABLE f (x TEXT)"}}"#,
    );
    assert!(r.contains("\"status\":200"), "{r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/db/exec","body":{"sql":"INSERT INTO f VALUES ('facade-ok')"}}"#,
    );
    assert!(r.contains("\"status\":200"), "{r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/db/query","body":{"sql":"SELECT x FROM f"}}"#,
    );
    assert!(r.contains("facade-ok"), "{r}");

    // AutoLock via Fassade (Default 300, dann 1 s im Test).
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/session/login","body":{"master_b64":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#,
    );
    assert!(r.contains("\"status\":200"), "{r}");
    z8run_browser::facade(r#"{"method":"POST","path":"/v1/session/check","body":{"now_ms":1000}}"#);
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/session/autolock","body":{"sec":1}}"#,
    );
    assert!(r.contains("\"autolock_sec\":1"), "{r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/session/check","body":{"now_ms":2500}}"#,
    );
    assert!(r.contains("\"locked\":true"), "{r}");

    // Nativ -> WASM: native Z8FC1-Datei im Browser entsiegeln.
    let native = include_bytes!("fixtures/native-db.z8fc");
    let plain = z8run_browser::open_sealed(&[9u8; 32], native).unwrap();
    assert!(plain.starts_with(b"SQLite format 3"), "native Fixture nicht lesbar");
    assert!(plain.windows(b"native-nach-wasm".len()).any(|w| w == b"native-nach-wasm"));
    println!("NATIVE_TO_WASM_OK bytes={}", plain.len());

    // Konflikt: aelterer OPFS-Stand + neuere S3-WAL => Replay + UI-Event.
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/conflict","body":{"local_wal":7,"local_hash":"aa","remote_wal":9,"remote_hash":"bb"}}"#,
    );
    assert!(r.contains("ReplayRemote"), "Konflikt-Event fehlt: {r}");
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/conflict","body":{"local_wal":9,"local_hash":"aa","remote_wal":9,"remote_hash":"bb"}}"#,
    );
    assert!(r.contains("ChainMismatch"), "Kettenkonflikt fehlt: {r}");

    // Offline-Regel: S3-Kontakt fehlt => SHUTDOWN.
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/s3/probe","body":{"ok":false}}"#,
    );
    assert!(r.contains("\"alive\":false"), "{r}");
}
