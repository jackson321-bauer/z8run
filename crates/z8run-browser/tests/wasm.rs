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

    // Offline-Regel: S3-Kontakt fehlt => SHUTDOWN.
    let r = z8run_browser::facade(
        r#"{"method":"POST","path":"/v1/s3/probe","body":{"ok":false}}"#,
    );
    assert!(r.contains("\"alive\":false"), "{r}");
}
