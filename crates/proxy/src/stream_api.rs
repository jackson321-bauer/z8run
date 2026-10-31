//! S4: Stream-Durchreichung. 12-Chunk-Blob (chunked) und Live-Zeilen (SSE)
//! laufen durch den Ringpuffer: RAM bleibt bei der Puffergroesse, Reihenfolge
//! bleibt erhalten.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use proxy_kern::stream::pump;
use proxy_kern::{ByteSink, ByteSource, ProxyError};
use sha2::{Digest, Sha256};

use crate::http::{bearer, ApiError};
use crate::service::ProxyService;

pub const CHUNKS: usize = 12;
pub const CHUNK_SIZE: usize = 1024 * 1024;
const RING: usize = 64 * 1024;

/// Deterministischer Chunk i: 1-basierter 4-Byte-LE-Index + Fuellbytes.
pub fn blob_chunk(i: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + CHUNK_SIZE);
    v.extend_from_slice(&((i + 1) as u32).to_le_bytes());
    v.extend(std::iter::repeat_n(((i as u8).wrapping_add(1)) | 0x80, CHUNK_SIZE));
    v
}

pub fn blob_sha_hex() -> String {
    let mut h = Sha256::new();
    for i in 0..CHUNKS {
        h.update(blob_chunk(i));
    }
    hex::encode(h.finalize())
}

pub fn blob_total() -> u64 {
    (CHUNKS * (CHUNK_SIZE + 4)) as u64
}

struct BlobSource {
    next: usize,
}

impl ByteSource for BlobSource {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProxyError> {
        if self.next >= CHUNKS {
            return Ok(None);
        }
        let i = self.next;
        self.next += 1;
        tracing::info!(chunk = i + 1, von = CHUNKS, "Blob-Chunk durchgereicht");
        Ok(Some(blob_chunk(i)))
    }
}

struct SseSource {
    next: usize,
}

impl ByteSource for SseSource {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProxyError> {
        if self.next >= CHUNKS {
            return Ok(None);
        }
        let i = self.next;
        self.next += 1;
        tracing::info!(event = i + 1, von = CHUNKS, "SSE-Event durchgereicht");
        Ok(Some(
            format!("data: {{\"seq\":{},\"text\":\"zeile-{i}\"}}\n\n", i + 1).into_bytes(),
        ))
    }
}

struct ChannelSink {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ByteSink for ChannelSink {
    fn write_chunk(&mut self, data: &[u8]) -> Result<(), ProxyError> {
        self.tx
            .blocking_send(data.to_vec())
            .map_err(|_| ProxyError::Stream("Client weg".into()))
    }
    fn finish(&mut self) -> Result<(), ProxyError> {
        Ok(())
    }
}

fn spawn_source(source: Box<dyn ByteSource>, cap: usize) -> axum::body::Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2);
    tokio::task::spawn_blocking(move || {
        let mut source = source;
        let mut sink = ChannelSink { tx };
        if let Err(e) = pump(source.as_mut(), &mut sink, cap) {
            tracing::warn!(error = %e, "Stream abgebrochen");
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|c| (Ok::<_, std::io::Error>(c), rx))
    });
    axum::body::Body::from_stream(stream)
}

async fn blob(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let body = spawn_source(
        Box::new(BlobSource { next: 0 }),
        RING,
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

async fn blob_meta(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    Ok(axum::Json(serde_json::json!({
        "chunks": CHUNKS,
        "chunk_size": CHUNK_SIZE,
        "total": blob_total(),
        "sha256": blob_sha_hex(),
    })))
}

async fn events(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let body = spawn_source(Box::new(SseSource { next: 0 }), 4096);
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new()
        .route("/v1/stream/blob", get(blob))
        .route("/v1/stream/blob/meta", get(blob_meta))
        .route("/v1/stream/events", get(events))
}
