//! PQC-Beweisclient: verbindet mit DERSELBEN Bibliothek (rustls + aws-lc-rs)
//! und gibt die verhandelte Schlüsselgruppe aus. Erwartung: X25519MLKEM768.
//! `--legacy` bietet nur klassische Gruppen an (Fallback-Beweis).

use std::sync::Arc;

use clap::Parser;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

#[derive(Parser)]
#[command(name = "z8-tls-proof", about = "PQC-TLS Handshake-Beweis")]
struct Cli {
    /// host:port
    #[arg(default_value = "riss.zerr-remote.de:443")]
    target: String,
    /// SNI-Name (Default: Host aus target)
    #[arg(long)]
    sni: Option<String>,
    /// Nur klassische Gruppen anbieten (Fallback-Beweis)
    #[arg(long)]
    legacy: bool,
}

fn provider(legacy: bool) -> rustls::crypto::CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups.sort_by_key(|g| match g.name() {
        rustls::NamedGroup::X25519MLKEM768 => 0,
        _ => 1,
    });
    if legacy {
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
    }
    p
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let sni = cli
        .sni
        .clone()
        .unwrap_or_else(|| cli.target.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| cli.target.clone()));
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider(cli.legacy)))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(&cli.target).await?;
    let name = ServerName::try_from(sni.clone()).map_err(|e| anyhow::anyhow!("SNI: {e}"))?;
    let tls = connector.connect(name, tcp).await?;
    let (_, conn) = tls.get_ref();
    let group = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_else(|| "UNBEKANNT".into());
    let pqc = group.contains("MLKEM");
    println!("TARGET {} SNI {} MODUS {} GRUPPE {} PQC {}", cli.target, sni,
        if cli.legacy { "legacy" } else { "pqc" }, group, pqc);
    // Optionaler Body-Beweis: HTTP/1.1 GET / ueber denselben Stream.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tls = tls;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: riss.zerr-remote.de\r\nConnection: close\r\n\r\n").await?;
    let mut buf = vec![0u8; 4096];
    let n = tls.read(&mut buf).await.unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    let status = head.lines().next().unwrap_or("").to_string();
    println!("HTTP {}", status);
    Ok(())
}
