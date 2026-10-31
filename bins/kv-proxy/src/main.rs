//! kv-proxy nativ: Dienst und duenne Steuerung.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use proxy_native::adapters::login;
use proxy_native::{http, ProxyConfig, ProxyService, UdsDbClient};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "kv-proxy", about = "Z8 Proxy (PROXY-1)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dienst starten (Default)
    Serve,
    /// Laufenden Dienst abfragen
    Status,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => serve(),
        Cmd::Status => {
            let cfg = ProxyConfig::default();
            let body = tokio::runtime::Runtime::new()?.block_on(uds_get(
                &cfg.admin_socket,
                "/v1/status",
            ))?;
            println!("{body}");
            Ok(())
        }
    }
}

fn serve() -> anyhow::Result<()> {
    let cfg = ProxyConfig::default();
    let svc = Arc::new(
        ProxyService::new(cfg.clone()).with_db(Arc::new(UdsDbClient::new(cfg.db_socket.clone()))),
    );
    tokio::runtime::Runtime::new()?.block_on(async move {
        {
            let svc = svc.clone();
            let path = cfg.admin_socket.clone();
            tokio::spawn(async move {
                if let Err(e) = http::serve_uds(svc, path).await {
                    tracing::warn!(error = %e, "Admin-UDS beendet");
                }
            });
        }
        {
            let svc = svc.clone();
            let path = cfg.login_socket.clone();
            tokio::spawn(async move {
                if let Err(e) = login::serve_login(svc, path).await {
                    tracing::warn!(error = %e, "Login-Handoff beendet");
                }
            });
        }
        http::serve_tcp(svc).await
    })
}

async fn uds_get(
    path: &std::path::Path,
    uri: &str,
) -> anyhow::Result<String> {
    use http_body_util::BodyExt;
    let stream = tokio::net::UnixStream::connect(path).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let body = resp.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&body).to_string())
}
