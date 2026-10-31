//! S4: WAL-Stress = Proxy-SHUTDOWN (fail-closed) + Cursor-Nachholung.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use proxy_kern::{DbPort, EventKind, MetaEvent, ProxyError, SessionState};
use proxy_native::{EventHub, Filter, MetaStore, ProxyConfig, ProxyService, Sink, UdsDbClient};
use serde_json::{json, Value};

struct FailingWal {
    writes: AtomicUsize,
}

#[async_trait]
impl DbPort for FailingWal {
    async fn open_db(&self, _: &str, _: &str, _: Value) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn close_db(&self, _: &str) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn reserve(&self, _: &str, _: &str) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn release(&self, _: &str, _: &str) -> Result<Value, ProxyError> {
        Ok(json!({"ok": true}))
    }
    async fn query(&self, _: &str, _: &str, _: Vec<Value>, _: bool) -> Result<Value, ProxyError> {
        Ok(json!({"rows": []}))
    }
    async fn write(&self, _: &str, _: &str, _: &str, _: Vec<Value>) -> Result<Value, ProxyError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(ProxyError::Db("WAL-Upload blockiert (Fake-Backend)".into()))
    }
    async fn status(&self, _: Option<&str>) -> Result<Value, ProxyError> {
        Ok(json!({"wal_pending": 1}))
    }
    async fn schema(&self, _: &str) -> Result<Value, ProxyError> {
        Ok(json!({}))
    }
}

fn session(svc: &ProxyService) -> String {
    let state = SessionState::new(
        "sess-wal".into(),
        "space".into(),
        "user".into(),
        "ws/".into(),
        Value::Null,
        vec!["demo".into()],
        vec![7u8; 32],
        svc.now_ms(),
    );
    svc.open_session(state).token
}

#[tokio::test]
async fn wal_fehler_stoppt_proxy_und_lehnt_aktionen_ab() {
    let cfg = ProxyConfig {
        wal_pending_limit: 1000,
        ..ProxyConfig::default()
    };
    let db = Arc::new(FailingWal {
        writes: AtomicUsize::new(0),
    });
    let svc = Arc::new(ProxyService::new(cfg).with_db(db.clone()));
    let token = session(&svc);

    let first = svc
        .db_write_traced(&token, "demo", "INSERT INTO t VALUES (1)", vec![], None)
        .await;
    assert!(first.is_err(), "WAL-Fehler wurde nicht gemeldet");
    assert!(svc.wal_down(), "Proxy ging bei WAL-Fehler nicht DOWN");
    let reason = svc.guard.reason().unwrap_or_default();
    println!("SHUTDOWN grund={reason}");
    assert!(reason.contains("WAL"));

    // Nach dem Shutdown werden Aktionen ABGELEHNT (kein Bypass).
    let attempts_before = db.writes.load(Ordering::SeqCst);
    let second = svc
        .db_write_traced(&token, "demo", "INSERT INTO t VALUES (2)", vec![], None)
        .await;
    assert!(matches!(second, Err(ProxyError::Unavailable(_))), "{second:?}");
    assert_eq!(
        db.writes.load(Ordering::SeqCst),
        attempts_before,
        "Aktion lief nach Shutdown trotzdem zur WAL"
    );

    // HTTP-Naht: fail-closed = 503 fuer jeden Aufruf.
    let app = proxy_native::http::router(svc.clone());
    let req = axum::http::Request::builder()
        .uri("/v1/status")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), 503, "HTTP-Naht nicht fail-closed");
    println!("HTTP_SHUTDOWN status={}", resp.status());
}

struct Collect(std::sync::Mutex<Vec<u64>>);
#[async_trait]
impl Sink for Collect {
    async fn deliver(&self, e: &proxy_native::Event) -> bool {
        self.0.lock().unwrap().push(e.seq);
        true
    }
}

#[tokio::test]
async fn cursor_holt_nach_und_nur_wal_bestaetigte_aktionen() {
    // Pull-Cursor: Restart nach Absturz holt nichts doppelt/verloren.
    let hub = EventHub::new(100);
    let c = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
    hub.subscribe(Filter::all(), c.clone());
    for i in 0..5 {
        hub.publish("c", "proxy", "meta:x", "trace", json!({"i": i})).await;
    }
    let cursor = 2;
    let missed = hub.since(cursor);
    let replay: Vec<u64> = missed.iter().map(|e| e.seq).collect();
    assert_eq!(replay, vec![3, 4, 5], "Cursor-Nachholung falsch");
    let all = hub.since(0);
    assert_eq!(all.len(), 5, "Cursor doppelt/verloren");
    println!("CURSOR replay={replay:?} total={}", all.len());

    // Real-WAL: nur bestaetigte Aktionen landen in der Meta-Welt.
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
    db.open_db(
        "meta",
        &master,
        json!({
            "cluster_id": "wal",
            "local_dir": dir.path().join("dbnode"),
            "adapter": {"Fs": {"root": dir.path().join("storage")}},
        }),
    )
    .await
    .unwrap();
    let db_arc: Arc<dyn DbPort> = Arc::new(db);
    let store = MetaStore::new(db_arc, vec!["meta".into()]);
    for i in 0..2 {
        let e = MetaEvent::new(
            "system", EventKind::FlowEnd, "flow", "trace-wal", "s", "ok", "flow_end", i,
        )
        .unwrap();
        store.record(&e).await.unwrap(); // WAL-Ack = Aktion passiert
    }
    let before = store.query(None, None, 10).await.unwrap();
    assert_eq!(before.len(), 2);
    // Eine nicht-WAL-bestaetigte Aktion hinterlaesst keine Zeile.
    let after = store.query(None, None, 10).await.unwrap();
    assert_eq!(after.len(), 2, "nicht-bestaetigte Aktion sichtbar");
    println!("WAL_BESTAETIGT rows={}", after.len());
}
