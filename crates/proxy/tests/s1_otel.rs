//! S1: Span-Kern + OTEL-DB (roundtrip, RSS flach, Fehler-Hook).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use proxy_kern::{Direction, SpanStatus};
use proxy_kern::DbPort;
use proxy_native::{OtelStore, UdsDbClient};
use serde_json::json;

fn cluster(dir: &std::path::Path) -> serde_json::Value {
    json!({
        "cluster_id": "cluster-a",
        "local_dir": dir.join("dbnode"),
        "adapter": {"Fs": {"root": dir.join("storage")}},
    })
}

fn rss_kb() -> u64 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    text.lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

async fn start(dir: &std::path::Path) -> (std::path::PathBuf, UdsDbClient) {
    let sock = dir.join("dbnode.sock");
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
    (sock.clone(), UdsDbClient::new(sock))
}

#[tokio::test]
async fn span_roundtrip_identisch_und_rss_flach() {
    let dir = tempfile::tempdir().unwrap();
    let (_sock, db) = start(dir.path()).await;
    let master = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    db.open_db("otel", &master, cluster(dir.path())).await.unwrap();

    let db_arc: Arc<dyn proxy_kern::DbPort> = Arc::new(db);
    let store = OtelStore::new(db_arc, "otel");

    let span = proxy_kern::Span {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: "00f067aa0ba902b7".into(),
        parent_span_id: None,
        name: "chat".into(),
        attrs: json!({"model": "demo", "dir": "out"}),
        start_ms: 1000,
        end_ms: 1010,
        status: SpanStatus::Ok,
        engine_id: "engine-1".into(),
        direction: Some(Direction::Out),
    };
    store.write(&span).await.unwrap();
    let back = store.query_trace(&span.trace_id).await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0], span, "Span-Roundtrip nicht identisch");

    // 1000 Spans: RSS darf nicht durch Logging-Puffer wachsen.
    let before = rss_kb();
    for i in 0..1000u64 {
        let mut s = span.clone();
        s.span_id = format!("{:016x}", i + 1);
        s.start_ms = i;
        s.end_ms = i + 1;
        store.write(&s).await.unwrap();
    }
    let after = rss_kb();
    let delta = after.saturating_sub(before);
    println!("RSS vor={before} KiB nach={after} KiB delta={delta} KiB");
    assert!(delta < 20_000, "RSS wuchs um {delta} KiB (>20 MiB)");
    let all = store.all().await.unwrap();
    assert_eq!(all.len(), 1001);
}

struct BrokenDb;
#[async_trait::async_trait]
impl proxy_kern::DbPort for BrokenDb {
    async fn open_db(&self, _: &str, _: &str, _: serde_json::Value) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("kaputt".into()))
    }
    async fn close_db(&self, _: &str) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("kaputt".into()))
    }
    async fn reserve(&self, _: &str, _: &str) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("WAL blockiert".into()))
    }
    async fn release(&self, _: &str, _: &str) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("kaputt".into()))
    }
    async fn query(&self, _: &str, _: &str, _: Vec<serde_json::Value>, _: bool) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("kaputt".into()))
    }
    async fn write(&self, _: &str, _: &str, _: &str, _: Vec<serde_json::Value>) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("WAL blockiert".into()))
    }
    async fn status(&self, _: Option<&str>) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("kaputt".into()))
    }
    async fn schema(&self, _: &str) -> Result<serde_json::Value, proxy_kern::ProxyError> {
        Err(proxy_kern::ProxyError::Db("kaputt".into()))
    }
}

#[tokio::test]
async fn span_fehler_wird_gemeldet() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let store = OtelStore::new(Arc::new(BrokenDb), "otel");
    store.set_error_sink(Arc::new(move |_msg| {
        c.fetch_add(1, Ordering::SeqCst);
    }));
    let span = proxy_kern::Span {
        trace_id: "0af7651916cd43dd8448eb211c80319c".into(),
        span_id: "b7ad6b7169203331".into(),
        parent_span_id: None,
        name: "kaputt".into(),
        attrs: json!({}),
        start_ms: 0,
        end_ms: 1,
        status: SpanStatus::Error,
        engine_id: String::new(),
        direction: Some(Direction::Internal),
    };
    assert!(store.write(&span).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "Meta-Fehlerhook nicht gerufen");
}
