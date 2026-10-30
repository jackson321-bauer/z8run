//! S1 (g)(h)(i): Chunk-Streaming (Manifest/Playlist), Manipulations-Erkennung,
//! Kurz-Blob = genau 1 Chunk. RSS bleibt flach.

mod common;

use common::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use z8run_core::dbnode::{DummyBackend, StorageBackend};

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[tokio::test]
async fn g_aufnahme_12_chunks_playlist_und_rss() {
    let base = temp_base("blob-g");
    let node = node();
    node.open_db("db-g", &master(), cluster("c1", &base)).await.unwrap();
    node.reserve("db-g", "rec").unwrap();

    let stueck: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let mut original = Vec::new();
    let rss0 = rss_kb();
    let sampler = RssSampler::start();
    let m = node.blob_session_begin("db-g", "rec", "jason", "video/mp4").await.unwrap();
    for i in 0..12u64 {
        let mut d = stueck.clone();
        d[0] = i as u8;
        original.extend_from_slice(&d);
        node.blob_session_append("db-g", "rec", &m.session_id, &d, 30_000).await.unwrap();
    }
    let fin = node.blob_session_finish("db-g", "rec", &m.session_id).await.unwrap();
    let peak = sampler.stop();
    let anstieg = peak.saturating_sub(rss0);
    assert!(anstieg < 10 * 1024, "RSS-Anstieg {anstieg} KiB >= 10 MB");

    assert_eq!(fin.chunk_ids.len(), 12);
    assert_eq!(fin.dauer_ms, 12 * 30_000);
    assert_eq!(fin.gesamt_sha256, sha(&original));
    let out = node.blob_session_get_bytes("db-g", &m.session_id).await.unwrap();
    assert_eq!(sha(&original), sha(&out), "Wiedergabe != Original");
}

#[tokio::test]
async fn h_chunk_manipulation_wird_erkannt() {
    let base = temp_base("blob-h");
    let node = node();
    let storage = Arc::new(DummyBackend::new());
    node.open_db_with_storage("db-h", &master(), cluster("c1", &base), storage.clone())
        .await
        .unwrap();
    node.reserve("db-h", "rec").unwrap();
    let stueck = vec![9u8; 32 * 1024];

    let m = node.blob_session_begin("db-h", "rec", "o", "audio/wav").await.unwrap();
    for i in 0..12u64 {
        let mut d = stueck.clone();
        d[0] = i as u8;
        node.blob_session_append("db-h", "rec", &m.session_id, &d, 1000).await.unwrap();
    }
    let fin = node.blob_session_finish("db-h", "rec", &m.session_id).await.unwrap();

    // (1) Reihenfolge im Manifest tauschen -> Gesamt-SHA256 schlägt fehl.
    let mut rev = fin.chunk_ids.clone();
    rev.reverse();
    node.write(
        "db-h",
        "rec",
        "UPDATE linefs_blob_sessions SET chunk_ids = ?1 WHERE session_id = ?2",
        vec![serde_json::json!(serde_json::to_string(&rev).unwrap()), serde_json::json!(m.session_id)],
    )
    .await
    .unwrap();
    let e = node.blob_session_get_bytes("db-h", &m.session_id).await.unwrap_err();
    assert!(e.code == "BLOB_INTEGRITY" || e.code == "BLOB_SEAL", "code={}", e.code);

    // (2) Chunk 7 durch Chunk 6 ersetzen -> AAD/Key passt nicht.
    // Reihenfolge zurücksetzen.
    node.write(
        "db-h",
        "rec",
        "UPDATE linefs_blob_sessions SET chunk_ids = ?1 WHERE session_id = ?2",
        vec![serde_json::json!(serde_json::to_string(&fin.chunk_ids).unwrap()), serde_json::json!(m.session_id)],
    )
    .await
    .unwrap();
    let c6 = &fin.chunk_ids[6];
    let c7 = &fin.chunk_ids[7];
    let k6 = format!("blobs/db-h/{c6}/00000000.part");
    let k7 = format!("blobs/db-h/{c7}/00000000.part");
    let fremd = storage.read(&k6).await.unwrap().unwrap();
    storage.write(&k7, &fremd).await.unwrap();
    let e2 = node.blob_session_get_bytes("db-h", &m.session_id).await.unwrap_err();
    assert!(e2.code == "BLOB_SEAL" || e2.code == "BLOB_INTEGRITY", "code={}", e2.code);
}

#[tokio::test]
async fn i_kurz_blob_ist_genau_ein_chunk() {
    let base = temp_base("blob-i");
    let node = node();
    node.open_db("db-i", &master(), cluster("c1", &base)).await.unwrap();
    node.reserve("db-i", "rec").unwrap();
    let m = node.blob_session_begin("db-i", "rec", "o", "audio/wav").await.unwrap();
    let d = b"kurze-session-unter-chunkgroesse".to_vec();
    node.blob_session_append("db-i", "rec", &m.session_id, &d, 2500).await.unwrap();
    let fin = node.blob_session_finish("db-i", "rec", &m.session_id).await.unwrap();
    assert_eq!(fin.chunk_ids.len(), 1, "Kurz-Session muss genau 1 Chunk sein");
    let alle = node.blob_list("db-i").unwrap();
    let chunk = alle.iter().find(|b| b.blob_id == fin.chunk_ids[0]).unwrap();
    assert_eq!(chunk.parts, 1, "Kurz-Blob = 1 Part");
    assert_eq!(node.blob_session_get_bytes("db-i", &m.session_id).await.unwrap(), d);
}
