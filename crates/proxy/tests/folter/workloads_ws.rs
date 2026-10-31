//! Token-Rotation und eingehende WebSocket-Streams unter Last.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use proxy_kern::SessionState;
use proxy_native::frame::{Frame, TYP_MEDIA};
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
                HeaderValue::from_str(&format!("folter/ws-{c}")).ok()?,
            );
            let (mut ws, _) = tokio_tungstenite::connect_async(req).await.ok()?;
            for i in 0..5u8 {
                let framed = Frame::with_flags(TYP_MEDIA, 0, 1, 0, vec![i; 64])
                    .ok()?
                    .encode()
                    .ok()?;
                ws.send(Message::Binary(framed.into())).await.ok()?;
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



/// p99-Relay-Latenz AM ECHTEN `/v1/stream`-Endpunkt (nicht nur Registry):
/// Producer (live) sendet Binärrahmen, Consumer (subscribe) empfängt.
pub async fn relay_p99_ws(url: String, token: String, frames: u64) -> u64 {
    use tokio_tungstenite::tungstenite::Message;
    async fn conn(
        url: &str,
        token: &str,
        typ: &str,
        channel: &str,
    ) -> Option<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
        let mut req = url.into_client_request().ok()?;
        req.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).ok()?,
        );
        req.headers_mut().insert("x-z8-stream-type", HeaderValue::from_str(typ).ok()?);
        req.headers_mut()
            .insert("x-z8-channel", HeaderValue::from_str(channel).ok()?);
        tokio_tungstenite::connect_async(req).await.ok().map(|(w, _)| w)
    }
    let Some(mut producer) = conn(&url, &token, "live", "folter/wsrelay").await else {
        return u64::MAX;
    };
    let Some(mut consumer) = conn(&url, &token, "subscribe", "folter/wsrelay").await else {
        return u64::MAX;
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut lat = Vec::with_capacity(frames as usize);
    for i in 0..frames {
        let sent = Instant::now();
        let mut payload = sent.elapsed().as_nanos().to_le_bytes().to_vec();
        payload.extend_from_slice(&(i as u64).to_le_bytes());
        let Ok(frame) = Frame::with_flags(TYP_MEDIA, 0, 1, 0, payload) else {
            return u64::MAX;
        };
        let Ok(framed) = frame.encode() else {
            return u64::MAX;
        };
        if producer.send(Message::Binary(framed.into())).await.is_err() {
            return u64::MAX;
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(1), consumer.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => {
                    let _ = Frame::decode(&b);
                    lat.push(sent.elapsed().as_micros() as u64);
                    break;
                }
                Ok(Some(Ok(_))) => continue,
                _ => return u64::MAX,
            }
        }
    }
    let _ = producer.close(None).await;
    let _ = consumer.close(None).await;
    if lat.is_empty() {
        return u64::MAX;
    }
    lat.sort_unstable();
    let idx = (lat.len() as f64 * 0.99).ceil() as usize;
    lat[idx.saturating_sub(1).min(lat.len() - 1)]
}
