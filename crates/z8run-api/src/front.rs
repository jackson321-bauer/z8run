//! EIN PORT (F20): z8run bindet 443 direkt mit PQC-TLS und routet per Pfad:
//! /proxy/* -> kv-proxy, /login/* -> kv-login (intern), alles andere -> Engine.
//! Die alten oeffentlichen Ports 7710 werden damit unnoetig.

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::Body;
use axum::response::Response;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Debug)]
pub struct FrontConfig {
    pub bind: String,
    pub port: u16,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub proxy_addr: SocketAddr,
    pub login_addr: SocketAddr,
}

impl FrontConfig {
    /// Aus Umgebung; `None` = kein HTTPS-Listener (z.B. Tests/Desktop).
    pub fn from_env() -> Option<Self> {
        let port = std::env::var("Z8_HTTPS_PORT").ok()?;
        if port.is_empty() {
            return None;
        }
        let cert = std::env::var("Z8_TLS_CERT").ok()?;
        let key = std::env::var("Z8_TLS_KEY").ok()?;
        let proxy = std::env::var("Z8_PROXY_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:7800".into());
        let login = std::env::var("Z8_LOGIN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:7710".into());
        Some(Self {
            bind: std::env::var("Z8_HTTPS_BIND").unwrap_or_else(|_| "0.0.0.0".into()),
            port: port.parse().ok()?,
            cert: cert.into(),
            key: key.into(),
            proxy_addr: proxy.parse().ok()?,
            login_addr: login.parse().ok()?,
        })
    }
}

/// Startet den TLS-Ein-Port-Front mit PQC (blockiert bis Listener stirbt).
pub async fn serve(app: Router, cfg: FrontConfig) -> anyhow::Result<()> {
    let addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        address = %addr,
        proxy = %cfg.proxy_addr,
        login = %cfg.login_addr,
        "Ein-Port-Front bereit (443)"
    );
    serve_listener(app, cfg, listener).await
}

/// Wie `serve`, aber mit bereits gebundenem Listener (Tests/Port 0).
pub async fn serve_listener(
    app: Router,
    cfg: FrontConfig,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let tls = crate::tls::load_server_config(&cfg.cert, &cfg.key)
        .map_err(|e| anyhow::anyhow!(e))?;
    if !crate::tls::offers_mlkem(&tls) {
        anyhow::bail!("TLS-Config bietet X25519MLKEM768 nicht an (falsches Backend?)");
    }
    tracing::info!(
        gruppen = ?crate::tls::offered_groups(&tls),
        "PQC-TLS aktiv (ML-KEM angeboten)"
    );
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(acceptor, tcp, peer, app, cfg).await {
                tracing::debug!(error = %e, "TLS-Verbindung beendet");
            }
        });
    }
}

async fn handle(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    app: Router,
    cfg: FrontConfig,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(tcp).await?;
    let (_, conn) = tls.get_ref();
    let group = crate::tls::negotiated_group_name(conn);
    let pqc = group.as_deref().is_some_and(|g| g.contains("MLKEM"));
    tracing::info!(peer = %peer, gruppe = ?group, pqc, "TLS-Handshake verhandelt");
    let io = TokioIo::new(tls);
    let proxy = cfg.proxy_addr;
    let login = cfg.login_addr;
    let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
        let app = app.clone();
        async move {
            let (parts, body) = req.into_parts();
            let req = hyper::Request::from_parts(parts, Body::new(body));
            Ok::<_, std::convert::Infallible>(route(req, app, proxy, login, peer).await)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await?;
    Ok(())
}

async fn route(
    mut req: hyper::Request<Body>,
    app: Router,
    proxy: SocketAddr,
    login: SocketAddr,
    peer: SocketAddr,
) -> Response {
    let path = req.uri().path().to_string();
    // /proxy/* -> kv-proxy; /login/v1/* und /kvlogin/* -> kv-login.
    // Exakt /login bleibt die z8run-SPA (sonst waere die UI tot).
    let target = if path == "/proxy" || path.starts_with("/proxy/") {
        Some((proxy, "/proxy"))
    } else if path.starts_with("/login/v1/") {
        Some((login, "/login"))
    } else if path == "/kvlogin" || path.starts_with("/kvlogin/") {
        Some((login, "/kvlogin"))
    } else {
        None
    };
    if let Some((addr, prefix)) = target {
        let rest = &path[prefix.len()..];
        let rest = if rest.is_empty() { "/" } else { rest };
        let pq = match req.uri().query() {
            Some(q) => format!("{rest}?{q}"),
            None => rest.to_string(),
        };
        let uri = format!("http://{addr}{pq}");
        match uri.parse() {
            Ok(u) => *req.uri_mut() = u,
            Err(e) => return fehler(400, &format!("Ziel-URI: {e}")),
        }
        {
            let h = req.headers_mut();
            for k in [
                "connection", "keep-alive", "transfer-encoding", "upgrade",
                "proxy-authorization", "proxy-authenticate", "te",
            ] {
                h.remove(k);
            }
            if let Ok(v) = addr.to_string().parse() {
                h.insert("host", v);
            }
        }
        return reverse(req, addr).await;
    }
    req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
    match tower::ServiceExt::oneshot(app, req).await {
        Ok(resp) => resp,
        Err(e) => match e {},
    }
}

async fn reverse(req: hyper::Request<Body>, addr: SocketAddr) -> Response {
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
        let _ = conn.await;
    });
    match sender.send_request(req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            Response::from_parts(parts, Body::new(body))
        }
        Err(e) => fehler(502, &format!("upstream Antwort: {e}")),
    }
}

fn fehler(status: u16, text: &str) -> Response {
    let status = axum::http::StatusCode::from_u16(status)
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let body = serde_json::json!({"code": "GATEWAY", "error": text});
    (status, axum::Json(body)).into_response()
}

use axum::response::IntoResponse;
