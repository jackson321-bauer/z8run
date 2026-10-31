//! Token-Rotation und eingehende WebSocket-Streams unter Last.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::SinkExt;
use proxy_kern::SessionState;
use proxy_native::ProxyService;
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

pub async fn rotations(svc: Arc<ProxyService>, sessions: u64, per: u64) -> u64 {
    let mut tokens = Vec::new();
    for i in 0..sessions {
        let state = SessionState::new(
            format!("folter-rot-{i}"), "space".into(), "user".into(), "ws/".into(),
            json!([]), vec!["demo".into()], b"master".to_vec(), 1,
        );
        tokens.push(svc.open_session(state).token);
    }
    let counter = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for tok in tokens {
        let svc = svc.clone();
        let counter = counter.clone();
        tasks.push(tokio::spawn(async move {
            let mut t = tok;
            for _ in 0..per {
                if let Ok(g) = svc.rotate(&t) {
                    t = g.token;
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    counter.load(Ordering::Relaxed)
}

pub async fn ws_streams(url: String, token: String, round: u64) -> usize {
    let mut tasks = Vec::new();
    for c in 0..100u64 {
        let url = url.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move {
            let mut req = url.into_client_request().ok()?;
            req.headers_mut().insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}")).ok()?,
            );
            req.headers_mut().insert("x-z8-stream-type", HeaderValue::from_static("live"));
            req.headers_mut().insert(
                "x-z8-channel",
                HeaderValue::from_str(&format!("folter/ws-{round}-{c}")).ok()?,
            );
            let (mut ws, _) = tokio_tungstenite::connect_async(req).await.ok()?;
            for i in 0..5u8 {
                ws.send(Message::Binary(vec![i; 64].into())).await.ok()?;
            }
            let _ = ws.close(None).await;
            Some(())
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.ok().flatten().is_some() {
            ok += 1;
        }
    }
    ok
}

