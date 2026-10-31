//! S5: PQC-TLS-Beweis — Server BIETET MLKEM an UND verhandelt es;
//! klassischer Client faellt auf X25519 zurueck.

use std::sync::Arc;

use rustls::pki_types::ServerName;

fn legacy_provider() -> rustls::crypto::CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups = p
        .kx_groups
        .into_iter()
        .filter(|g| {
            !matches!(
                g.name(),
                rustls::NamedGroup::X25519MLKEM768 | rustls::NamedGroup::secp256r1MLKEM768
            )
        })
        .collect();
    p
}

async fn handshake(legacy: bool) -> String {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let server_cfg = z8run_api::tls::server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    assert!(
        z8run_api::tls::offers_mlkem(&server_cfg),
        "Server-Config bietet MLKEM nicht an"
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _tls = acceptor.accept(tcp).await.unwrap();
        // Verbindung kurz offen halten.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let provider = if legacy {
        legacy_provider()
    } else {
        (*z8run_api::tls::provider()).clone()
    };
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let (_, conn) = tls.get_ref();
    conn.negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_else(|| "UNBEKANNT".into())
}

#[tokio::test]
async fn pqc_handshake_verhandelt_mlkem_und_legacy_faellt_zurueck() {
    let pqc = handshake(false).await;
    println!("PQC_CLIENT gruppe={pqc}");
    assert_eq!(pqc, "X25519MLKEM768", "PQC-Handshake verhandelte {pqc}");
    let legacy = handshake(true).await;
    println!("LEGACY_CLIENT gruppe={legacy}");
    assert_eq!(legacy, "X25519", "Fallback verhandelte {legacy}");
}
