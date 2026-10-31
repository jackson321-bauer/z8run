//! S5: Ein-Port-Front lokal — PQC-Handshake + Pfad-Routing
//! / -> Engine, /proxy/* -> kv-proxy, /login/v1/* -> kv-login, /login -> Engine.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use rustls::pki_types::ServerName;

async fn upstream(name: &'static str) -> std::net::SocketAddr {
    let app = Router::new().fallback(move |uri: axum::http::Uri| async move {
        format!("{name}:{}", uri.path())
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn engine() -> Router {
    Router::new()
        .route("/", get(|| async { "engine:/".to_string() }))
        .route("/login", get(|| async { "engine:/login" }))
        .fallback(|| async { "engine:fallback".to_string() })
}

#[tokio::test]
async fn ein_port_handshake_und_pfad_routing() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let proxy = upstream("proxy").await;
    let login = upstream("login").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = z8run_api::front::FrontConfig {
        bind: "127.0.0.1".into(),
        port: addr.port(),
        cert: cert_path,
        key: key_path,
        proxy_addr: proxy,
        login_addr: login,
    };
    tokio::spawn(async move {
        let _ = z8run_api::front::serve_listener(engine(), cfg, listener).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let ccfg = rustls::ClientConfig::builder_with_provider(z8run_api::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));

    async fn get(connector: &tokio_rustls::TlsConnector, addr: std::net::SocketAddr, path: &str)
        -> (String, String, String)
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let group = tls
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()))
            .unwrap_or_default();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        let status = text.lines().next().unwrap_or("").to_string();
        (group, status, body)
    }

    // Engine
    let (group, status, body) = get(&connector, addr, "/").await;
    assert_eq!(group, "X25519MLKEM768", "Handshake nicht PQC");
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "engine:/");
    // SPA-Login bleibt Engine
    let (_, _, body) = get(&connector, addr, "/login").await;
    assert_eq!(body, "engine:/login", "/login darf nicht zu kv-login");
    // /proxy/*
    let (_, status, body) = get(&connector, addr, "/proxy/v1/status").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "proxy:/v1/status");
    // /login/v1/*
    let (_, status, body) = get(&connector, addr, "/login/v1/health").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "login:/v1/health");
    // /kvlogin/* Kompatibilitaet
    let (_, _, body) = get(&connector, addr, "/kvlogin/v1/login").await;
    assert_eq!(body, "login:/v1/login");
    println!("EIN_PORT gruppe={group} routing ok");
}
