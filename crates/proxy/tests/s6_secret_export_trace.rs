//! S6: Secret-Injektion (nur Ausgang), Redaktion, Trace-Ende-zu-Ende,
//! JSONL-Export + MANIFEST-Siegel; kein Secret in Spans/Meta/Antworten.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use proxy_kern::{DbPort, EventKind, LlmPort, ProxyError, SessionState};
use proxy_native::{ProxyConfig, ProxyService, UdsDbClient};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SECRET: &str = "SK-TOPSECRET-9";
const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN: &str = "00f067aa0ba902b7";

struct CaptureLlm {
    seen: Mutex<String>,
}

#[async_trait]
impl LlmPort for CaptureLlm {
    async fn complete(&self, system: &str, user: &str) -> Result<Value, ProxyError> {
        *self.seen.lock().unwrap() = system.to_string();
        Ok(json!({"model": "mock", "user": user, "echo_system": system}))
    }
}

fn cluster(dir: &std::path::Path) -> Value {
    json!({
        "cluster_id": "s6",
        "local_dir": dir.join("dbnode"),
        "adapter": {"Fs": {"root": dir.join("storage")}},
    })
}

#[tokio::test]
async fn secret_injektion_export_und_ein_trace() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("dbnode.sock");
    let s = sock.clone();
    tokio::spawn(async move {
        let _ = z8run_core::dbnode::msg_uds::serve(s).await;
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let db = UdsDbClient::new(sock);
    let master = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    for db_id in ["demo", "otel", "meta", "meta-cluster"] {
        db.open_db(db_id, &master, cluster(dir.path())).await.unwrap();
    }
    let export_key = vec![0x2a; 32];
    let export_dir = dir.path().join("export");
    let cfg = ProxyConfig {
        otel_db: "otel".into(),
        meta_db: "meta".into(),
        cluster_meta_db: "meta-cluster".into(),
        export_dir: export_dir.clone(),
        export_key: hex::encode(&export_key),
        ..ProxyConfig::default()
    };
    let db_arc: Arc<dyn DbPort> = Arc::new(db);
    let mut svc = ProxyService::new(cfg).with_db(db_arc);
    let seen = Arc::new(CaptureLlm {
        seen: Mutex::new(String::new()),
    });
    svc.llm = seen.clone() as Arc<dyn LlmPort>;
    svc.secrets.insert("ncp", "api_key", SECRET);
    svc.prompts
        .insert("sys", b"System {{secret:ncp/api_key}} bereit.".to_vec());
    let svc = Arc::new(svc);

    let state = SessionState::new(
        "sess-s6".into(), "space".into(), "user".into(), "ws/".into(),
        Value::Null, vec!["demo".into()], vec![7u8; 32], svc.now_ms(),
    );
    let token = svc.open_session(state).token;
    let traceparent = format!("00-{TRACE}-{SPAN}-01");

    let out = svc
        .llm_call_traced(&token, "sys", "frage", Some(&traceparent))
        .await
        .unwrap();
    // Injektion am Ausgang: das LLM hat den Klartext gesehen.
    let system_seen = seen.seen.lock().unwrap().clone();
    assert!(system_seen.contains(SECRET), "Secret nicht injiziert: {system_seen}");
    println!("LLM_SAH Secret (erwartet) len={}", system_seen.len());
    // Antwort enthaelt NIE das Secret (Redaktion).
    let out_text = out.to_string();
    assert!(!out_text.contains(SECRET), "Secret in Antwort: {out_text}");
    println!("ANTWORT_REDIGIERT ok trace={}", out["trace_id"]);

    // Echter Logging-Sink (DB-Persistenz) Latenz: Aktion -> Senke.
    let t = std::time::Instant::now();
    svc.record_meta(
        "system", EventKind::FlowStart, "bench", TRACE, "sess-s6", "ok", "bench",
    )
    .await;
    let d = t.elapsed();
    println!("META_SINK_LATENZ_US {}", d.as_micros());
    assert!(
        d < std::time::Duration::from_millis(10),
        "Logging-Sink-Latenz {d:?} >= 10 ms"
    );

    // Spans + Meta im selben Trace, ohne Secret.
    let spans = svc.span_query(TRACE).await.unwrap();
    assert!(!spans.is_empty(), "kein Span im Trace");
    let spans_text = serde_json::to_string(&spans).unwrap();
    assert!(!spans_text.contains(SECRET), "Secret in Spans");
    let meta = svc.meta_query(Some(TRACE), None, 100).await.unwrap();
    let meta_text = meta.to_string();
    assert!(!meta_text.contains(SECRET), "Secret in Meta");
    assert!(meta_text.contains("call_happened"), "Meta-Decke fehlt: {meta_text}");
    let full = svc.trace_full(TRACE).await.unwrap();
    assert!(full["span_count"].as_u64().unwrap() >= 1);
    assert!(full["meta_count"].as_u64().unwrap() >= 1);
    println!("TRACE_FULL spans={} meta={}", full["span_count"], full["meta_count"]);

    // Export JSONL + MANIFEST sha256 + Siegel.
    let manifest = svc.export_otel(Some(TRACE)).await.unwrap();
    assert!(manifest["sealed"].as_str().unwrap().len() == 64);
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    for f in files {
        let name = f["name"].as_str().unwrap();
        let path = export_dir.join(name);
        let bytes = std::fs::read(&path).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        assert_eq!(hex::encode(h.finalize()), f["sha256"].as_str().unwrap());
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(SECRET), "Secret in Export-Datei {name}");
    }
    assert!(
        proxy_native::export::verify(&export_key, &manifest),
        "Manifest-Siegel ungueltig"
    );
    let manifest_text = manifest.to_string();
    assert!(!manifest_text.contains(SECRET), "Secret im Manifest");
    println!("EXPORT dateien={} siegel=ok", files.len());
}
