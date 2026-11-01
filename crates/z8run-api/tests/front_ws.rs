//! S2-Front: WebSocket-Upgrade durch den PQC-TLS-Ein-Port (443) ueber UDS/udsv3.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

async fn echo_upstream(kontext: &'static str, dir: &std::path::Path, name: &str) -> PathBuf {
    let app = Router::new().route(
        "/v1/stream",
        get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut s| async move {
                while let Some(Ok(msg)) = s.recv().await {
                    if let Message::Binary(b) = msg {
                        let _ = s.send(Message::Binary(b)).await;
                    }
                }
            })
        }),
    );
    let path = dir.join(format!("{name}.sock"));
    let uds = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match uds.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let app = app.clone();
            tokio::spawn(async move {
                let io = z8run_core::udsv3_stream::server_io(stream, kontext).unwrap();
                let io = TokioIo::new(io);
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let app = app.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
                            match tower::ServiceExt::oneshot(app, req).await {
                                Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                                Err(e) => match e {},
                            }
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    path
}

#[tokio::test]
async fn ws_upgrade_durch_pqc_front() {
    std::env::set_var("Z8_UDSV3_MASTER", "0123456789abcdef0123456789abcdef");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let proxy = echo_upstream("admin", dir.path(), "proxy").await;
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
        let _ = z8run_api::front::serve_listener(Router::new(), cfg, listener).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let ccfg = rustls::ClientConfig::builder_with_provider(z8run_api::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let group = tls
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_default();
    assert_eq!(group, "X25519MLKEM768");

    let mut req = "ws://localhost/proxy/v1/stream".into_client_request().unwrap();
    req.headers_mut()
        .insert("host", HeaderValue::from_static("localhost"));
    req.headers_mut()
        .insert("x-z8-stream-type", HeaderValue::from_static("live"));
    let (mut ws, resp) = tokio_tungstenite::client_async(req, tls).await.unwrap();
    assert_eq!(resp.status().as_u16(), 101);

    ws.send(tokio_tungstenite::tungstenite::Message::Binary(vec![1u8, 2, 3].into()))
        .await
        .unwrap();
    let got = loop {
        match ws.next().await.unwrap().unwrap() {
            tokio_tungstenite::tungstenite::Message::Binary(b) => break b,
            _ => continue,
        }
    };
    assert_eq!(&got[..], &[1u8, 2, 3]);
    println!("FRONT_WS gruppe={group} upgrade=101 echo=ok");
}
