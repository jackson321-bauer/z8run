//! S1: Token-Rotation ueber die echte HTTP-Schicht (401-Klartext-Code).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use proxy_kern::{Clock, Random, SessionState};
use proxy_native::{http, ProxyConfig, ProxyService};
use tower::ServiceExt;

struct FakeClock(AtomicU64);
impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct SeqRandom(AtomicU64);
impl Random for SeqRandom {
    fn fill(&self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.0.fetch_add(1, Ordering::SeqCst) % 251) as u8;
        }
    }
}

fn service() -> (Arc<FakeClock>, Arc<ProxyService>) {
    let clock = Arc::new(FakeClock(AtomicU64::new(10_000)));
    let cfg = ProxyConfig {
        token_ttl_ms: 1_000,
        token_grace_ms: 200,
        ..ProxyConfig::default()
    };
    let svc = Arc::new(ProxyService::with_parts(
        cfg,
        clock.clone(),
        Arc::new(SeqRandom(AtomicU64::new(7))),
    ));
    (clock, svc)
}

async fn call(
    svc: &Arc<ProxyService>,
    method: &str,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = http::router(svc.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn rotation_und_fehler_auth_ueber_http() {
    let (clock, svc) = service();
    let state = SessionState::new(
        "s1".into(),
        "space".into(),
        "user".into(),
        "ws/".into(),
        serde_json::Value::Null,
        vec!["db1".into()],
        b"master".to_vec(),
        10_000,
    );
    let grant = svc.open_session(state);

    let (status, body) = call(&svc, "POST", "/v1/session/rotate", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "UNAUTHORIZED");

    let (status, body) = call(
        &svc,
        "POST",
        "/v1/session/rotate",
        Some(&grant.token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second = body["token"].as_str().unwrap().to_string();
    assert_ne!(second, grant.token);

    let (status, _) = call(&svc, "GET", "/v1/session", Some(&grant.token)).await;
    assert_eq!(status, StatusCode::OK, "Alt-Token in Grace");

    clock.0.fetch_add(250, Ordering::SeqCst);
    let (status, body) = call(&svc, "GET", "/v1/session", Some(&grant.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "TOKEN_EXPIRED");

    let (status, _) = call(&svc, "GET", "/v1/session", Some(&second)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&svc, "POST", "/v1/session/logout", Some(&second)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&svc, "GET", "/v1/session", Some(&second)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
