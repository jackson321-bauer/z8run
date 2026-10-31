//! S3: Aufnahme parallel (Blob-Session) + Wiedergabe ueber Kanaele +
//! Migration: alte SSE/chunked-Endpunkte sind weg (404).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use proxy_kern::{DbPort, SessionState};
use proxy_native::frame::{Frame, TYP_MEDIA};
use proxy_native::playback::{blob_chunk, blob_sha_hex, publish_chunks, CHUNKS, CHUNK_SIZE};
use proxy_native::{http, ProxyConfig, ProxyService};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn service() -> (Arc<ProxyService>, String) {
    let svc = Arc::new(ProxyService::new(ProxyConfig::default()));
    let state = SessionState::new(
        "s3".into(), "space".into(), "user".into(), "ws/".into(), json!([]),
        vec!["demo".into()], b"master".to_vec(), 1,
    );
    let token = svc.open_session(state).token;
    (svc, token)
}

async fn server(svc: Arc<ProxyService>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, http::router(svc)).await.unwrap() });
    format!("ws://{addr}/v1/stream")
}

async fn connect(url: &str, token: &str, typ: &str, ch: &str, peer: Option<&str>, id: &str) -> Ws {
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("authorization", HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
    for (k, v) in [("x-z8-stream-type", typ), ("x-z8-channel", ch), ("x-z8-identity", id)] {
        req.headers_mut().insert(k, HeaderValue::from_str(v).unwrap());
    }
    if let Some(p) = peer {
        req.headers_mut().insert("x-z8-peer-channel", HeaderValue::from_str(p).unwrap());
    }
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws
}

async fn send_bin(ws: &mut Ws, b: &[u8]) {
    let framed = Frame::with_flags(TYP_MEDIA, 0, 1, 0, b.to_vec())
        .unwrap()
        .encode()
        .unwrap();
    ws.send(Message::Binary(framed.into())).await.unwrap();
}

async fn recv_payload(ws: &mut Ws) -> Vec<u8> {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await.expect("Timeout").expect("zu").expect("ws");
        if let Message::Binary(b) = msg {
            return b[16..].to_vec();
        }
    }
}

async fn get(svc: Arc<ProxyService>, uri: &str) -> StatusCode {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    http::router(svc).oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn blob_playback_12_chunks_ueber_kanal_und_alte_endpunkte_404() {
    let (svc, token) = service();
    let url = server(svc.clone()).await;
    let mut sub = connect(&url, &token, "subscribe", "demo/playback", None, "app").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let chunks: Vec<Vec<u8>> = (0..CHUNKS).map(blob_chunk).collect();
    assert_eq!(publish_chunks(&svc.streams, "demo/playback", &chunks).unwrap(), 12);

    let mut all = Vec::new();
    for i in 0..CHUNKS {
        let payload = recv_payload(&mut sub).await;
        assert_eq!(payload.len(), CHUNK_SIZE);
        let idx = u32::from_le_bytes(payload[..4].try_into().unwrap());
        assert_eq!(idx as usize, i + 1, "Chunk-Reihenfolge verletzt");
        all.extend_from_slice(&payload);
    }
    assert_eq!(all.len() as u64, (CHUNKS * CHUNK_SIZE) as u64);
    assert_eq!(hex::encode(Sha256::digest(&all)), blob_sha_hex());
    println!("PLAYBACK_KANAL chunks=12 sha={} reihenfolge=1..12", blob_sha_hex());

    for uri in ["/v1/stream/blob", "/v1/stream/blob/meta", "/v1/stream/events"] {
        assert_eq!(get(svc.clone(), uri).await, StatusCode::NOT_FOUND, "{uri} lebt noch");
    }
    println!("ALTE_ENDPUNKTE blob/events/meta = 404");
}

#[tokio::test]
async fn aufnahme_duplex_alle_frames_sha_gleich_und_wiedergabe() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("dbnode.sock");
    let s = sock.clone();
    tokio::spawn(async move { let _ = z8run_core::dbnode::msg_uds::serve(s).await; });
    for _ in 0..100 {
        if sock.exists() { break; }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let db = proxy_native::UdsDbClient::new(sock);
    let master = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let cluster = json!({"cluster_id": "s3", "local_dir": dir.path().join("dbnode"),
        "adapter": {"Fs": {"root": dir.path().join("storage")}}});
    db.open_db("demo", &master, cluster).await.unwrap();
    let db_arc: Arc<dyn proxy_kern::DbPort> = Arc::new(db);
    let svc = Arc::new(ProxyService::new(ProxyConfig::default()).with_db(db_arc));
    let state = SessionState::new("s3-duplex".into(), "space".into(), "user".into(), "ws/".into(),
        json!([]), vec!["demo".into()], vec![7u8; 32], 1);
    let token = svc.open_session(state).token;
    let url = server(svc.clone()).await;
    let mut a = connect(&url, &token, "duplex", "call/a", Some("call/b"), "alice").await;
    let mut b = connect(&url, &token, "duplex", "call/b", Some("call/a"), "bob").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Warm-up: DB-Caches/Allokatoren einmal anlegen, DANN RSS messen.
    svc.recording_start("demo", "warmup/a", "warm", "audio/opus").await.unwrap();
    for i in 0..100u32 {
        svc.streams
            .publish("warmup/a", TYP_MEDIA, i.to_le_bytes().to_vec())
            .unwrap();
    }
    let wm = svc.recording_stop("warmup/a").await.unwrap();
    let wsid = wm["session_id"].as_str().unwrap().to_string();
    svc.streams.open("warmup/play").unwrap();
    svc.playback_recording("demo", &wsid, "warmup/play", 64 * 1024)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    svc.recording_start("demo", "call/a", "alice", "audio/opus").await.unwrap();
    let rss0 = rss_kb();
    let mut expected = Vec::new();
    let mut hasher = Sha256::new();
    for i in 0..200u32 {
        let mut p = vec![0u8; 160];
        p[0..4].copy_from_slice(&i.to_le_bytes());
        p[159] = 0xAB;
        expected.extend_from_slice(&p);
        hasher.update(&p);
        send_bin(&mut a, &p).await;
        assert_eq!(recv_payload(&mut b).await, p);
    }
    let manifest = svc.recording_stop("call/a").await.unwrap();
    let sid = manifest["session_id"].as_str().unwrap().to_string();
    assert_eq!(manifest["gesamt_sha256"].as_str().unwrap(), hex::encode(hasher.finalize()));
    assert!(!manifest["chunk_ids"].as_array().unwrap().is_empty());
    let rss1 = rss_kb();
    println!("AUFNAHME frames=200 session={sid} chunks={} rss_delta_kb={}",
        manifest["chunk_ids"].as_array().unwrap().len(), rss1.saturating_sub(rss0));
    assert!(rss1.saturating_sub(rss0) < 64 * 1024, "RSS waechst: {rss0}->{rss1} KiB");

    let mut play = connect(&url, &token, "subscribe", "call/playback", None, "player").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let frames = svc.playback_recording("demo", &sid, "call/playback", 64 * 1024).await.unwrap();
    let mut got = Vec::new();
    for _ in 0..frames {
        got.extend_from_slice(&recv_payload(&mut play).await);
    }
    assert_eq!(got, expected, "Wiedergabe nicht byte-identisch");
    println!("WIEDERGABE_KANAL frames={frames} bytes={} sha_gleich=ja", got.len());

    // OEFFENTLICHE API (der Weg einer App): start -> push -> stop -> playback.
    let app = http::router(svc.clone());
    let (st, _) = post_json(
        app.clone(),
        "/v1/recording/start",
        &token,
        json!({"db_id":"demo","channel":"call/http","owner":"http","mime":"audio/opus"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    svc.streams
        .publish("call/http", TYP_MEDIA, b"http-frame".to_vec())
        .unwrap();
    let (st, v) = post_json(
        app.clone(),
        "/v1/recording/stop",
        &token,
        json!({"channel":"call/http"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let hsid = v["manifest"]["session_id"].as_str().unwrap().to_string();
    svc.streams.open("call/http-play").unwrap();
    let (st, v) = post_json(
        app,
        "/v1/playback",
        &token,
        json!({"db_id":"demo","sid":hsid,"channel":"call/http-play","chunk_size":65536}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["frames"].as_u64().unwrap() >= 1);
    println!("RECORDING_HTTP start/stop/playback=ok");
}

async fn post_json(
    app: axum::Router,
    uri: &str,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

fn rss_kb() -> u64 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    text.lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}
