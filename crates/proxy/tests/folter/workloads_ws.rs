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

/// Szenario (f): 100 eingehende Streams GLEICHZEITIG offen halten und
/// WAEHRENDDESSEN die p99-Relay-Latenz am /v1/stream-Endpunkt messen.
pub async fn ws_streams(url: String, token: String, round: u64) -> (usize, u64) {
    let mut conns = Vec::new();
    for c in 0..100u64 {
        let mut req = match url.clone().into_client_request() {
            Ok(r) => r,
            Err(_) => continue,
        };
        req.headers_mut().insert(
            "authorization",
            match HeaderValue::from_str(&format!("Bearer {token}")) {
                Ok(v) => v,
                Err(_) => continue,
            },
        );
        req.headers_mut().insert("x-z8-stream-type", HeaderValue::from_static("live"));
        req.headers_mut().insert(
            "x-z8-channel",
            match HeaderValue::from_str(&format!("folter/ws-{c}")) {
                Ok(v) => v,
                Err(_) => continue,
            },
        );
        let Ok((mut ws, _)) = tokio_tungstenite::connect_async(req).await else {
            continue;
        };
        for i in 0..5u8 {
            let Ok(frame) = Frame::with_flags(TYP_MEDIA, 0, 1, 0, vec![i; 64]) else {
                break;
            };
            let Ok(framed) = frame.encode() else { break };
            let _ = ws.send(Message::Binary(framed.into())).await;
        }
        conns.push(ws);
    }
    let open = conns.len();
    // Alle 100 sind JETZT offen; p99 unter dieser Parallelitaet messen.
    let p99 = relay_p99_ws(url, token, 200).await;
    for mut ws in conns {
        let _ = ws.close(None).await;
    }
    let _ = round;
    (open, p99)
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
