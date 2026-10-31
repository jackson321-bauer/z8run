//! kv-proxy nativ: Dienst und duenne Steuerung.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use proxy_native::adapters::login;
use proxy_native::{bundle, http, FsStorage, ProxyConfig, ProxyService, UdsDbClient};
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
    /// prompts.enc aus einer name<TAB>text-Datei versiegeln (Deploy)
    SealPrompts {
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long)]
        prompts: std::path::PathBuf,
    },
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
        Cmd::SealPrompts { out, prompts } => seal_prompts(&out, &prompts),
    }
}

fn seal_prompts(out: &std::path::Path, prompts: &std::path::Path) -> anyhow::Result<()> {
    let key = bundle_key().ok_or_else(|| anyhow::anyhow!("KV_PROXY_BUNDLE_KEY fehlt/ungueltig"))?;
    let bundle_id = std::env::var("KV_PROXY_BUNDLE_ID").unwrap_or_else(|_| "echo".to_string());
    let text = std::fs::read_to_string(prompts)?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, content) = line
            .split_once('\t')
            .ok_or_else(|| anyhow::anyhow!("Prompt-Zeile ohne Tab: {line}"))?;
        entries.push((name.to_string(), content.as_bytes().to_vec()));
    }
    let sealed = bundle::seal_prompts(&key, &bundle_id, &entries)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, sealed)?;
    println!("prompts.enc geschrieben: {} Eintraege -> {}", entries.len(), out.display());
    Ok(())
}

fn serve() -> anyhow::Result<()> {
    let cfg = ProxyConfig::default();
    let svc = Arc::new(
        ProxyService::new(cfg.clone()).with_db(Arc::new(UdsDbClient::new(cfg.db_socket.clone()))),
    );
    tokio::runtime::Runtime::new()?.block_on(async move {
        {
            let storage = FsStorage::new(cfg.bundle.clone());
            let key = bundle_key();
            match bundle::bootstrap(&svc, &storage, "", key.as_deref()).await {
                Ok(b) => tracing::info!(app = %b.manifest.name, "Bundle aktiv"),
                Err(e) => tracing::warn!(error = %e, "Kein Plugin-Bundle geladen"),
            }
        }
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

fn bundle_key() -> Option<Vec<u8>> {
    let raw = std::env::var("KV_PROXY_BUNDLE_KEY").ok()?;
    let t = raw.trim();
    let hexs = t.strip_prefix("0x").unwrap_or(t);
    if hexs.len() == 64 && hexs.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(hexs).ok();
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(t).ok()
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
