//! S2: Login-Handoff -> DB ueber Message-Naht; Scope + Gleichheit.

use std::sync::Arc;

use base64::Engine as _;
use proxy_kern::{DbPort, ProxyError};
use proxy_native::adapters::login;
use proxy_native::{ProxyConfig, ProxyService, UdsDbClient};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn master_b64() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

async fn login_raw(path: &std::path::Path, body: &str) -> Value {
    let mut s = tokio::net::UnixStream::connect(path).await.unwrap();
    s.write_all(body.as_bytes()).await.unwrap();
    s.write_all(b"\n").await.unwrap();
    let (rd, _wr) = s.into_split();
    let mut line = String::new();
    BufReader::new(rd).read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

async fn login_http(path: &std::path::Path, body: &str) -> (String, Value) {
    let mut s = tokio::net::UnixStream::connect(path).await.unwrap();
    let req = format!(
        "POST /login HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = s.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&out).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head.to_string(), serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn login_query_gleichheit_scope_und_master_nur_ram() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("dbnode.sock");
    let sock2 = sock.clone();
    tokio::spawn(async move {
        let _ = z8run_core::dbnode::msg_uds::serve(sock2).await;
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let cfg = ProxyConfig {
        dbnode_dir: dir.path().join("dbnode"),
        db_socket: sock.clone(),
        token_ttl_ms: 60_000,
        token_grace_ms: 1_000,
        ..ProxyConfig::default()
    };
    let svc = Arc::new(
        ProxyService::new(cfg.clone()).with_db(Arc::new(UdsDbClient::new(sock.clone()))),
    );
    let login_sock = dir.path().join("login.sock");
    {
        let svc = svc.clone();
        let p = login_sock.clone();
        tokio::spawn(async move {
            let _ = login::serve_login(svc, p).await;
        });
    }
    for _ in 0..100 {
        if login_sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let payload = json!({
        "event": "kv3-session",
        "addr_space": "testspace",
        "addr_user": "tester",
        "master_key_b64": master_b64(),
        "workspace_bucket": "workspaces/testspace/",
        "engines": ["demo"],
        "dbs": ["demo", "meta"],
    })
    .to_string();

    let reply = login_raw(&login_sock, &payload).await;
    assert_eq!(reply["ok"], true, "Login: {reply}");
    let token = reply["token"].as_str().unwrap().to_string();
    assert!(reply["dbs"].as_array().unwrap().len() == 2);

    // Schreiben ueber den Proxy.
    svc.db_write(
        &token,
        "demo",
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, note TEXT)",
        vec![],
    )
    .await
    .unwrap();
    svc.db_write(
        &token,
        "demo",
        "INSERT INTO t (note) VALUES (?1)",
        vec![json!("hallo-proxy")],
    )
    .await
    .unwrap();

    let via_proxy = svc
        .db_query(&token, "demo", "SELECT id, note FROM t ORDER BY id", vec![], true)
        .await
        .unwrap();

    // Direkt am DB-Node (gleiche Engine, Message-Naht) — Zeilen muessen gleich sein.
    let direct = UdsDbClient::new(sock.clone());
    let via_direct = direct
        .query("demo", "SELECT id, note FROM t ORDER BY id", vec![], true)
        .await
        .unwrap();
    assert_eq!(via_proxy, via_direct, "Proxy-Zeilen != DB-Node-Zeilen");
    assert!(via_proxy.to_string().contains("hallo-proxy"));

    // Fremde db_id => NOT_IN_SCOPE / 403.
    let err = svc
        .db_query(&token, "fremd", "SELECT 1", vec![], true)
        .await
        .unwrap_err();
    assert!(matches!(err, ProxyError::NotInScope));
    assert_eq!(err.status(), 403);

    // Master nur RAM: nie in SessionInfo/JSON.
    let info = svc.authenticate(&token).unwrap();
    let text = serde_json::to_string(&info).unwrap();
    assert!(!text.contains(&master_b64()));
    assert!(!format!("{info:?}").contains(&master_b64()));

    // Logout raeumt Session + Master (Drop zeroize).
    svc.logout(&token).unwrap();
    assert!(svc.authenticate(&token).is_err());

    // HTTP-Login-Form (unix-out) funktioniert ebenfalls.
    let (head, http_reply) = login_http(&login_sock, &payload).await;
    assert!(head.contains("200"), "HTTP-Login: {head}");
    assert_eq!(http_reply["ok"], true);
}
