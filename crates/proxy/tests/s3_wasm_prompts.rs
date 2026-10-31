//! S3: Echo-App-Roundtrip, Prompt-Nie-Sichtbar, falsches Siegel, FS/Net-Trap.

use std::sync::Arc;

use proxy_kern::{ProxyError, SessionState};
use proxy_native::adapters::wasm::WasmKvApp;
use proxy_native::bundle::{self, seal_prompts};
use proxy_native::{FsStorage, ProxyConfig, ProxyService};
use serde_json::json;
use sha2::{Digest, Sha256};

const PROMPT: &str = "PROMPT-GEHEIM-12345";

fn write_bundle(dir: &std::path::Path, key: &[u8], prompts: &[(String, Vec<u8>)]) {
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/echo/echo.wasm"
    ))
    .unwrap();
    std::fs::write(dir.join("app.wasm"), wasm).unwrap();
    let manifest = json!({
        "name": "echo",
        "version": "0.1.0",
        "app": "app.wasm",
        "prompts": "prompts.enc",
        "description": "Echo-Beweisapp",
        "capabilities": []
    });
    std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
    let sealed = seal_prompts(key, "echo", prompts).unwrap();
    std::fs::write(dir.join("prompts.enc"), sealed).unwrap();
}

fn service() -> (Arc<ProxyService>, String) {
    let svc = Arc::new(ProxyService::new(ProxyConfig::default()));
    let state = SessionState::new(
        "s3-session".into(),
        "space".into(),
        "user".into(),
        "ws/".into(),
        json!([]),
        vec!["demo".into()],
        b"master".to_vec(),
        1,
    );
    let token = svc.open_session(state).token;
    (svc, token)
}

#[tokio::test]
async fn echo_prompt_siegel_und_capability_trap() {
    let dir = tempfile::tempdir().unwrap();
    let key = [9u8; 32];
    write_bundle(
        dir.path(),
        &key,
        &[("system_secret".to_string(), PROMPT.as_bytes().to_vec())],
    );
    let (svc, token) = service();
    let storage = FsStorage::new(dir.path());
    let loaded = bundle::bootstrap(&svc, &storage, "", Some(&key))
        .await
        .unwrap();
    assert_eq!(loaded.manifest.name, "echo");
    assert_eq!(svc.prompts.len(), 1);
    assert!(svc.prompts.contains("system_secret"));

    let apps = svc.app_list(&token).unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].name, "echo");

    // Echo-Roundtrip + echte Signatur (SHA-256 ueber die Input-Bytes).
    let input = json!({"msg": "hallo echo", "n": 7, "nested": {"a": [1, 2]}});
    let out = svc.app_call(&token, "echo", &input).unwrap();
    assert_eq!(out.payload["ok"], true);
    assert_eq!(out.payload["echo"], input);
    assert_eq!(out.payload["prompt_used"], serde_json::Value::Null);
    let signed = serde_json::to_vec(&input).unwrap();
    let expect = hex::encode(Sha256::digest(&signed));
    assert_eq!(out.payload["signature"], expect);
    assert_eq!(out.payload["signed_len"], signed.len() as u64);
    assert!(!out.payload.to_string().contains(PROMPT), "Prompt in App-Antwort");

    // LLM: Prompt wird injiziert, aber nie zurueckgegeben.
    let llm = svc.llm_call(&token, "system_secret", "frage").await.unwrap();
    assert_eq!(llm["system_injected"], true);
    assert!(llm["system_chars"].as_u64().unwrap() > 0);
    assert!(!llm.to_string().contains(PROMPT), "Prompt in LLM-Antwort");

    // Falsches Bundle-Siegel => Fehler.
    let sealed = std::fs::read(dir.path().join("prompts.enc")).unwrap();
    let wrong = bundle::open_prompts(&[8u8; 32], "echo", &sealed);
    assert!(matches!(wrong, Err(ProxyError::Bundle(_))), "{wrong:?}");
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    assert!(bundle::open_prompts(&key, "echo", &tampered).is_err());

    // App mit fs/net-Import: die Sandbox hat keine Host-Imports => Trap/Ablehnung.
    let trap_wat = r#"
        (module
          (import "wasi_snapshot_preview1" "path_open"
            (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "z8_alloc") (param i32) (result i32) i32.const 0)
          (func (export "z8_dealloc") (param i32 i32))
          (func (export "z8_process") (param i32 i32) (result i32) i32.const 0)
        )
    "#;
    let trap_wasm = wat::parse_str(trap_wat).unwrap();
    let trap = WasmKvApp::load("trap", "0.1.0", &trap_wasm, vec![]).err();
    assert!(matches!(trap, Some(ProxyError::Wasm(_))), "{trap:?}");
}
