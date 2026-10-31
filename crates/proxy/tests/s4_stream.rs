//! S4: 12-Chunk-Blob durch den Proxy (sha256 + Reihenfolge) und SSE-Reihenfolge.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use proxy_kern::SessionState;
use proxy_native::stream_api::{blob_sha_hex, blob_total, CHUNK_SIZE, CHUNKS};
use proxy_native::{http, ProxyConfig, ProxyService};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn service() -> (Arc<ProxyService>, String) {
    let svc = Arc::new(ProxyService::new(ProxyConfig::default()));
    let state = SessionState::new(
        "s4".into(),
        "space".into(),
        "user".into(),
        "ws/".into(),
        json!([]),
        vec!["demo".into()],
        b"master".to_vec(),
        1,
    );
    let token = svc.open_session(state).token;
    (svc, token)
}

async fn get(svc: &Arc<ProxyService>, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let resp = http::router(svc.clone())
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
}

#[tokio::test]
async fn blob_12_chunks_sha_und_reihenfolge_sowie_sse() {
    let (svc, token) = service();

    let (status, _) = get(&svc, "/v1/stream/blob", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = get(&svc, "/v1/stream/blob", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len() as u64, blob_total());
    assert_eq!(hex::encode(Sha256::digest(&body)), blob_sha_hex());

    // Reihenfolge: jeder Chunk traegt seinen LE-Index an den ersten 4 Bytes.
    let stride = CHUNK_SIZE + 4;
    assert_eq!(body.len(), CHUNKS * stride);
    for i in 0..CHUNKS {
        let start = i * stride;
        let idx = u32::from_le_bytes(body[start..start + 4].try_into().unwrap());
        assert_eq!(idx as usize, i + 1, "Chunk-Reihenfolge verletzt");
        assert!(body[start + 4..start + stride]
            .iter()
            .all(|b| *b == ((i as u8).wrapping_add(1)) | 0x80));
    }

    // SSE: 12 Ereignisse in Ordnung.
    let (status, events) = get(&svc, "/v1/stream/events", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(events).unwrap();
    let seqs: Vec<u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["seq"].as_u64())
        .collect();
    assert_eq!(seqs, (1..=CHUNKS as u64).collect::<Vec<_>>());
    assert_eq!(text.matches("data: ").count(), CHUNKS);
}
