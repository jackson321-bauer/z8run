//! Login-Handoff: Listener auf dem bestehenden KV3-Socket. Nimmt den
//! unveraenderten Login-Payload (roher JSON-Line ODER HTTP von `unix-out`),
//! oeffnet den DB-Scope ueber die Message-Naht und gibt ein rotierendes Token.
//! Payload/Master/Token werden NIE geloggt.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use proxy_kern::{ProxyError, SessionState};
use serde_json::{json, Value};

use crate::service::ProxyService;

const MAX_REQUEST: usize = 4 * 1024 * 1024;

pub async fn serve_login(svc: Arc<ProxyService>, path: std::path::PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = tokio::fs::remove_file(&path).await;
    let uds = tokio::net::UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(path = %path.display(), "Login-Handoff lauscht");
    loop {
        let (stream, _) = uds.accept().await?;
        let svc = svc.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(svc, stream).await {
                tracing::warn!(code = e.code(), "Login-Handoff abgelehnt");
            }
        });
    }
}

async fn handle(svc: Arc<ProxyService>, stream: tokio::net::UnixStream) -> Result<(), ProxyError> {
    let (mut rd, mut wr) = stream.into_split();
    let (http, body) = tokio::time::timeout(Duration::from_secs(10), read_request(&mut rd))
        .await
        .map_err(|_| ProxyError::BadRequest("Login-Timeout".into()))??;
    match process(&svc, &body).await {
        Ok(reply) => {
            let text = reply.to_string();
            let _ = write_reply(&mut wr, http, 200, &text).await;
            Ok(())
        }
        Err(e) => {
            tracing::warn!(code = e.code(), "Login-Handoff Fehler");
            let body = proxy_kern::ErrorBody::from_error(&e);
            let text = serde_json::to_string(&body).unwrap_or_default();
            let _ = write_reply(&mut wr, http, e.status(), &text).await;
            Err(e)
        }
    }
}

async fn read_request(
    rd: &mut tokio::net::unix::OwnedReadHalf,
) -> Result<(bool, Vec<u8>), ProxyError> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut http = None;
    let mut need = 0usize;
    loop {
        let n = rd
            .read(&mut tmp)
            .await
            .map_err(|e| ProxyError::BadRequest(format!("lesen: {e}")))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_REQUEST {
            return Err(ProxyError::BadRequest("Login-Payload zu gross".into()));
        }
        if http.is_none() {
            http = Some(starts_http(&buf));
        }
        if http == Some(true) {
            if let Some(pos) = find(&buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                need = pos + 4 + len;
                if buf.len() >= need {
                    break;
                }
            }
        } else if buf.contains(&b'\n') {
            break;
        }
    }
    let http = http.unwrap_or(false);
    let body = if http {
        let start = find(&buf, b"\r\n\r\n").map(|p| p + 4).unwrap_or(buf.len());
        buf[start..need.min(buf.len())].to_vec()
    } else {
        let end = buf.iter().position(|b| *b == b'\n').unwrap_or(buf.len());
        buf[..end].to_vec()
    };
    Ok((http, body))
}

fn starts_http(buf: &[u8]) -> bool {
    [b"POST ".as_slice(), b"GET ", b"PUT ", b"PATCH ", b"DELETE "]
        .iter()
        .any(|m| buf.starts_with(m))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

async fn write_reply(
    wr: &mut tokio::net::unix::OwnedWriteHalf,
    http: bool,
    status: u16,
    body: &str,
) -> Result<(), ProxyError> {
    use tokio::io::AsyncWriteExt;
    let text = if http {
        format!(
            "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            if status == 200 { "OK" } else { "Error" },
            body.len()
        )
    } else {
        format!("{body}\n")
    };
    wr.write_all(text.as_bytes())
        .await
        .map_err(|e| ProxyError::Internal(format!("Antwort schreiben: {e}")))?;
    let _ = wr.shutdown().await;
    Ok(())
}

/// Baut die Session aus dem unveraenderten Login-Payload.
pub async fn process(svc: &ProxyService, body: &[u8]) -> Result<Value, ProxyError> {
    let payload: Value = serde_json::from_slice(body)
        .map_err(|e| ProxyError::BadRequest(format!("kein JSON: {e}")))?;
    let master = extract_master(&payload)?;
    let addr_space = text(&payload, "addr_space");
    let addr_user = text(&payload, "addr_user");
    let workspace_bucket = text(&payload, "workspace_bucket");
    let engines = payload.get("engines").cloned().unwrap_or(Value::Null);
    let dbs = scope(&payload, &addr_space)?;
    let master_b64 = base64::engine::general_purpose::STANDARD.encode(&master);
    let cluster = cluster_value(svc, &addr_space)?;

    for db in &dbs {
        svc.db
            .open_db(db, &master_b64, cluster.clone())
            .await
            .map_err(|e| ProxyError::Db(format!("open {db}: {e}")))?;
    }

    let session_id = uuid::Uuid::now_v7().to_string();
    let state = SessionState::new(
        session_id.clone(),
        addr_space,
        addr_user,
        workspace_bucket,
        engines,
        dbs.clone(),
        master,
        svc.now_ms(),
    );
    let grant = svc.open_session(state);
    tracing::info!(session = %grant.session_id, dbs = dbs.len(), "Login-Session geoeffnet");
    Ok(json!({
        "status": 200,
        "ok": true,
        "session_id": grant.session_id,
        "token": grant.token,
        "expires_at_ms": grant.expires_at_ms,
        "dbs": dbs,
    }))
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn extract_master(payload: &Value) -> Result<Vec<u8>, ProxyError> {
    let candidate = ["master_key_b64", "master", "master_b64"]
        .iter()
        .find_map(|k| payload.get(*k).and_then(|v| v.as_str()))
        .or_else(|| {
            payload
                .get("proxy_session")
                .and_then(|p| p.get("master_key_b64"))
                .and_then(|v| v.as_str())
        });
    let raw = candidate.ok_or_else(|| {
        ProxyError::BadRequest("Login-Payload enthaelt keinen Masterkey".into())
    })?;
    let t = raw.trim();
    let hexs = t.strip_prefix("0x").unwrap_or(t);
    if hexs.len() == 64 && hexs.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v) = hex::decode(hexs) {
            return Ok(v);
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| ProxyError::BadRequest(format!("Masterkey weder Base64 noch Hex: {e}")))
}

/// Scope-Policy PROXY-1: explizite `dbs`-Liste, sonst die beiden vom Setup
/// erzeugten Nutzer-DBs.
fn scope(payload: &Value, addr_space: &str) -> Result<Vec<String>, ProxyError> {
    if addr_space.is_empty() {
        return Err(ProxyError::BadRequest("addr_space fehlt".into()));
    }
    if let Some(arr) = payload.get("dbs").and_then(|v| v.as_array()) {
        let dbs: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| is_safe_id(s))
            .map(|s| s.to_string())
            .collect();
        if !dbs.is_empty() {
            return Ok(dbs);
        }
    }
    Ok(vec!["demo".to_string(), "meta".to_string()])
}

fn is_safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn cluster_value(svc: &ProxyService, addr_space: &str) -> Result<Value, ProxyError> {
    if !is_safe_id(addr_space) {
        return Err(ProxyError::BadRequest("addr_space ungueltig".into()));
    }
    let dir = svc.cfg.dbnode_dir.join(addr_space);
    Ok(json!({
        "cluster_id": svc.cfg.cluster_id,
        "local_dir": dir,
        "adapter": {"Fs": {"root": dir.join("storage")}},
    }))
}
