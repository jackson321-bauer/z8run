//! EIN generischer Stream-Endpoint (G1): `/v1/stream` als WebSocket.
//! Session-Typ im Header: live | subscribe | duplex | relay. Control-Frames
//! sind JSON, Medien-Frames BINAER (16-B-Header) — Inhalt wird nie geparst.

use std::sync::Arc;

use axum::{
    extract::{
        ws::WebSocketUpgrade,
        State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use crate::channel::valid_channel;
use crate::http::ApiError;
use crate::service::ProxyService;

use proxy_kern::ProxyError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Live,
    Subscribe,
    Duplex,
    Relay,
}

impl Kind {
    fn parse(v: &str) -> Option<Self> {
        match v {
            "live" => Some(Self::Live),
            "subscribe" => Some(Self::Subscribe),
            "duplex" => Some(Self::Duplex),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

pub struct Setup {
    pub kind: Kind,
    pub identity: String,
    pub session_id: String,
    pub own: Option<String>,
    pub peer: Option<String>,
    pub subscribe: Vec<String>,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        return v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")).map(str::to_string);
    }
    let raw = headers.get("sec-websocket-protocol")?.to_str().ok()?;
    let mut parts = raw.split(',').map(str::trim);
    (parts.next() == Some("z8.jwt")).then_some(parts.next()?.to_string())
}

fn setup(headers: &HeaderMap, session_id: &str) -> Result<Setup, ProxyError> {
    let kind = Kind::parse(&header(headers, "x-z8-stream-type").unwrap_or_else(|| "live".into()))
        .ok_or_else(|| ProxyError::BadRequest("Session-Typ unbekannt".into()))?;
    let identity = header(headers, "x-z8-identity").unwrap_or_else(|| session_id.to_string());
    let channel = header(headers, "x-z8-channel");
    let peer = header(headers, "x-z8-peer-channel");
    let mut subscribe = Vec::new();
    let own = match kind {
        Kind::Subscribe => {
            let ch = channel.ok_or_else(|| ProxyError::BadRequest("x-z8-channel fehlt".into()))?;
            subscribe.push(ch);
            None
        }
        Kind::Live => {
            Some(channel.ok_or_else(|| ProxyError::BadRequest("x-z8-channel fehlt".into()))?)
        }
        Kind::Duplex | Kind::Relay => {
            let own = channel.ok_or_else(|| ProxyError::BadRequest("x-z8-channel fehlt".into()))?;
            let peer =
                peer.clone().ok_or_else(|| ProxyError::BadRequest("x-z8-peer-channel fehlt".into()))?;
            subscribe.push(peer.clone());
            Some(own)
        }
    };
    for ch in own.iter().chain(subscribe.iter()) {
        if !valid_channel(ch) {
            return Err(ProxyError::BadRequest("Kanalname ungueltig".into()));
        }
    }
    Ok(Setup { kind, identity, session_id: session_id.to_string(), own, peer, subscribe })
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new().route("/v1/stream", get(handler))
}

async fn handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(svc): State<Arc<ProxyService>>,
) -> Response {
    let Some(tok) = token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "Missing authentication token").into_response();
    };
    let info = match svc.authenticate(&tok) {
        Ok(i) => i,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response(),
    };
    let st = match setup(&headers, &info.session_id) {
        Ok(s) => s,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let via_proto = headers.contains_key("sec-websocket-protocol");
    let upgrade = if via_proto {
        ws.protocols(["z8.jwt"]).on_upgrade(move |s| crate::stream_conn::handle(s, svc, st))
    } else {
        ws.on_upgrade(move |s| crate::stream_conn::handle(s, svc, st))
    };
    upgrade
}

