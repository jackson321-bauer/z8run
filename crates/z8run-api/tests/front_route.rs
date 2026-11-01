//! S5: Ein-Port-Front lokal — PQC-Handshake + Pfad-Routing ueber UDS/udsv3.
//! / -> Engine, /proxy/* -> kv-proxy, /login/v1/* -> kv-login, /login -> Engine.

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;

fn test_master() {
    std::env::set_var(
        "Z8_UDSV3_MASTER",
        "0123456789abcdef0123456789abcdef",
    );
}

async fn upstream(name: &'static str, kontext: &'static str, dir: &std::path::Path) -> PathBuf {
    let path = dir.join(format!("{name}.sock"));
    let uds = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match uds.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let io = z8run_core::udsv3_stream::server_io(stream, kontext).unwrap();
                let io = TokioIo::new(io);
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| async move {
                        let body = format!("{name}:{}", req.uri().path());
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            axum::body::Body::from(body),
                        ))
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    path
}

fn engine() -> Router {
    Router::new()
        .route("/", get(|| async { "engine:/".to_string() }))
        .route("/login", get(|| async { "engine:/login".to_string() }))
        .fallback(|| async { "engine:fallback".to_string() })
}

#[tokio::test]
async fn ein_port_handshake_und_pfad_routing() {
    test_master();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let proxy = upstream("proxy", "admin", dir.path()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = z8run_api::front::FrontConfig {
        bind: "127.0.0.1".into(),
        port: addr.port(),
        cert: cert_path,
        key: key_path,
        proxy_socket: proxy,
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

    let (group, status, body) = get(&connector, addr, "/").await;
    assert_eq!(group, "X25519MLKEM768", "Handshake nicht PQC");
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "engine:/");
    let (_, _, body) = get(&connector, addr, "/login").await;
    assert_eq!(body, "engine:/login", "/login darf nicht zu kv-login");
    let (_, status, body) = get(&connector, addr, "/proxy/v1/status").await;
    assert!(status.contains("200"), "{status}");
    assert_eq!(body, "proxy:/v1/status");
    // /2-Login ist ENTFERNT: kein toter Socket-Pfad, klare 410-Antwort.
    let (_, status, body) = get(&connector, addr, "/login/v1/health").await;
    assert!(status.contains("410"), "{status}");
    assert!(body.contains("entfernt"), "{body}");
    let (_, status, _) = get(&connector, addr, "/kvlogin/v1/login").await;
    assert!(status.contains("410"), "{status}");
    println!("EIN_PORT gruppe={group} routing ok");
}
