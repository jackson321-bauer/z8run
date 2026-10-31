//! WebSocket-Upgrade durch den PQC-TLS-Ein-Port: 101 beantworten und
//! danach Bytes bidirektional tunneln (WS ueber 443). Aus front.rs ausgelagert.

use std::net::SocketAddr;

use axum::body::Body;
use axum::response::Response;
use hyper_util::rt::TokioIo;

use crate::front::fehler;

pub(crate) fn is_websocket_upgrade(req: &hyper::Request<Body>) -> bool {
    let upgrade = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = req
        .headers()
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    upgrade && connection
}

/// WebSocket-Upgrade durch den PQC-TLS-Front: 101 wird beantwortet und
/// danach werden Bytes bidirektional getunnelt (WS ueber 443).
pub(crate) async fn reverse_upgrade(mut req: hyper::Request<Body>, addr: SocketAddr) -> Response {
    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => return fehler(502, &format!("upstream {addr}: {e}")),
    };
    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(v) => v,
        Err(e) => return fehler(502, &format!("handshake: {e}")),
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let client_upgrade = hyper::upgrade::on(&mut req);
    let mut resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => return fehler(502, &format!("upstream Antwort: {e}")),
    };
    if resp.status() != axum::http::StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = resp.into_parts();
        return Response::from_parts(parts, Body::new(body));
    }
    let server_upgrade = hyper::upgrade::on(&mut resp);
    let (parts, _) = resp.into_parts();
    tokio::spawn(async move {
        let (client, server) = tokio::join!(client_upgrade, server_upgrade);
        match (client, server) {
            (Ok(c), Ok(s)) => {
                let mut c = TokioIo::new(c);
                let mut s = TokioIo::new(s);
                let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
            }
            _ => tracing::debug!("WS-Upgrade auf einer Seite fehlgeschlagen"),
        }
    });
    Response::from_parts(parts, Body::empty())
}

