//! Duenne Stream-Control-API (G1): open/subscribe/claim/release/push fuer
//! Canvas-Nodes und MCP. Der Medienpfad bleibt der WebSocket; hier laufen
//! nur Control-Aktionen plus ein begrenzter Poll fuer subscribe.

use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::http::{bearer, ApiError};
use crate::service::ProxyService;

#[derive(Deserialize)]
struct Ctl {
    action: String,
    channel: String,
    #[serde(default)]
    payload_b64: Option<String>,
    #[serde(default)]
    typ: Option<u8>,
    #[serde(default)]
    limit: Option<usize>,
}

fn socket_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1_000_000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

async fn ctl(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<Ctl>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let info = svc.authenticate(&token)?;
    let reg = svc.streams.clone();
    let ch = req.channel.as_str();
    // G3: Identitaet = authentifizierte Session (Client-Feld wird ignoriert).
    let identity = info.session_id.clone();
    match req.action.as_str() {
        "open" => {
            let id = reg.open(ch)?;
            svc.record_meta("app", proxy_kern::meta::EventKind::AppCall, ch, "", &identity, "ok", "stream_open").await;
            Ok(Json(json!({"ok": true, "channel": ch, "stream_id": id})))
        }
        "claim" => {
            let g = reg.claim(ch, &identity, socket_id())?;
            svc.record_meta("app", proxy_kern::meta::EventKind::AppCall, ch, "", &identity, "ok", "stream_claim").await;
            Ok(Json(json!({"ok": true, "claimed": ch, "stream_id": g.stream_id})))
        }
        "release" => {
            reg.release(ch, &identity)?;
            svc.record_meta("app", proxy_kern::meta::EventKind::AppCall, ch, "", &identity, "ok", "stream_release").await;
            Ok(Json(json!({"ok": true, "released": ch})))
        }
        "push" => {
            if !reg.may_publish(ch, &identity) {
                return Err(ApiError::from(proxy_kern::ProxyError::Stream(
                    "Push ohne Claim (Senderecht fehlt)".into(),
                )));
            }
            let data = B64
                .decode(req.payload_b64.unwrap_or_default())
                .map_err(|e| ApiError::from(proxy_kern::ProxyError::BadRequest(format!("payload_b64: {e}"))))?;
            let out = reg.publish(ch, req.typ.unwrap_or(crate::frame::TYP_MEDIA), data)?;
            svc.record_meta("app", proxy_kern::meta::EventKind::AppCall, ch, "", &identity, "ok", "stream_push").await;
            Ok(Json(json!({"ok": true, "seq": out.seq, "delivered": out.delivered})))
        }
        "subscribe" => {
            let sid = socket_id();
            let sub = reg.subscribe(ch, sid)?;
            let limit = req.limit.unwrap_or(64).min(1024);
            let mut frames = Vec::new();
            while frames.len() < limit {
                match tokio::time::timeout(Duration::from_millis(25), reg.recv(&sub)).await {
                    Ok(Some(raw)) => frames.push(B64.encode(&raw[..])),
                    _ => break,
                }
            }
            reg.unsubscribe(ch, sid);
            svc.record_meta("app", proxy_kern::meta::EventKind::AppCall, ch, "", &identity, "ok", "stream_subscribe").await;
            Ok(Json(json!({"ok": true, "channel": ch, "frames_b64": frames})))
        }
        other => Err(ApiError::from(proxy_kern::ProxyError::BadRequest(format!(
            "unbekannte Stream-Aktion: {other}"
        )))),
    }
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new().route("/v1/stream/ctl", post(ctl))
}
