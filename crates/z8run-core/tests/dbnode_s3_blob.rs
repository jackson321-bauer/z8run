//! S3: echtes DanubeData-S3 (NEUER Prefix dbs/test-blobs/), 3 Blobs (1KB/10MB/
//! 100MB) je 2 DBs auf 2 Clustern, Upload/Download quer, Cleanup rest=0.

mod common;

use common::*;
use kv_store::s3::S3Endpoint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use z8run_core::dbnode::types::{Adapter, ClusterConfig};

#[derive(Deserialize)]
struct S3Cfg {
    host: String,
    region: String,
    access_key: String,
    secret_key: String,
    bucket: String,
}

fn cfg() -> S3Cfg {
    let path = std::env::var("Z8_DBBOX_S3_CONFIG").unwrap_or_else(|_| "/etc/z8run/s3.json".into());
    serde_json::from_slice(&std::fs::read(&path).expect("S3-Config lesbar")).unwrap()
}

fn cluster_s3(id: &str, base: &std::path::Path, c: &S3Cfg, prefix: &str) -> ClusterConfig {
    ClusterConfig {
        cluster_id: id.into(),
        local_dir: base.into(),
        adapter: Adapter::S3 {
            host: c.host.clone(),
            region: c.region.clone(),
            access_key: c.access_key.clone(),
            secret_key: c.secret_key.clone(),
            bucket: c.bucket.clone(),
            prefix: prefix.into(),
        },
    }
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

async fn leere_prefix(ep: &S3Endpoint, bucket: &str, prefix: &str) {
    let objs = ep.list_objects(bucket, &format!("{prefix}/")).await.unwrap();
    for o in &objs {
        ep.delete_object(bucket, &o.key).await.unwrap();
    }
    let rest = ep.list_objects(bucket, &format!("{prefix}/")).await.unwrap();
    assert!(rest.is_empty(), "Prefix {prefix} nicht leer: {}", rest.len());
    println!("CLEANUP prefix={prefix} geloescht={} rest={}", objs.len(), rest.len());
}

#[tokio::test]
async fn s3_blobs_zwei_cluster_zwei_dbs_und_cleanup() {
    let c = cfg();
    let ep = S3Endpoint {
        host: c.host.clone(), region: c.region.clone(),
        access_key: c.access_key.clone(), secret_key: c.secret_key.clone(),
    };
    let base = temp_base("s3-blobs");
    let prefixes = [("c-a", "dbs/test-blobs/a"), ("c-b", "dbs/test-blobs/b")];
    for (_, p) in &prefixes {
        leere_prefix(&ep, &c.bucket, p).await;
    }
    let node = node();
    let dbs: Vec<(&str, &str, &str, std::path::PathBuf)> = vec![
        ("blob-a1", "c-a", "sa1", base.join("a")),
        ("blob-a2", "c-a", "sa2", base.join("a")),
        ("blob-b1", "c-b", "sb1", base.join("b")),
        ("blob-b2", "c-b", "sb2", base.join("b")),
    ];
    for (db, cid, sess, dir) in &dbs {
        let prefix = if *cid == "c-a" { "dbs/test-blobs/a" } else { "dbs/test-blobs/b" };
        node.open_db(db, &master(), cluster_s3(cid, dir, &c, prefix))
            .await
            .unwrap();
        node.reserve(db, sess).unwrap();
    }
    let daten: Vec<(&str, Vec<u8>)> = vec![
        ("1k", (0..1024).map(|i| (i % 251) as u8).collect()),
        ("10m", vec![0x11u8; 10 * 1024 * 1024]),
        ("100m", vec![0x22u8; 100 * 1024 * 1024]),
    ];
    // Upload: 12 Blobs (3 Größen x 4 DBs).
    let mut ids: Vec<(String, String, String)> = Vec::new();
    for (db, _, sess, _) in &dbs {
        for (label, bytes) in &daten {
            let m = node
                .blob_put_bytes(db, sess, "s3-test", label, "application/octet-stream", bytes)
                .await
                .unwrap();
            assert_eq!(m.sha256_klartext, sha(bytes), "{db}/{label} meta-sha");
            println!("UPLOAD db={db} size={label} blob={} parts={}", m.blob_id, m.parts);
            ids.push((db.to_string(), label.to_string(), m.blob_id));
        }
    }
    // Chiffre-Beweis direkt am ECHTEN S3: Rohobjekt != Klartext.
    {
        let (db, label, blob_id) = &ids[0];
        assert_eq!(label, "1k");
        let roh_key = format!("dbs/test-blobs/a/blobs/{db}/{blob_id}/00000000.part");
        let roh = ep.get_object(&c.bucket, &roh_key).await.unwrap();
        let klar = &daten[0].1;
        assert_ne!(&roh, klar, "S3 sieht Klartext!");
        assert!(!roh.windows(klar.len()).any(|w| w == klar.as_slice()), "Klartext im S3-Objekt");
        println!("S3_CIPHER_OK key={roh_key} roh_len={} klar_len={}", roh.len(), klar.len());
    }
    // Download quer (andere DB, ggf. anderer Cluster): Inhalt + sha prüfen.
    for (db, label, blob_id) in &ids {
        let erwartet = &daten.iter().find(|(l, _)| l == label).unwrap().1;
        let out = node.blob_get_bytes(db, blob_id).await.unwrap();
        assert_eq!(sha(erwartet), sha(&out), "download {db}/{label}");
    }
    println!("DOWNLOADS ok={}", ids.len());

    for (db, _, _, _) in &dbs {
        node.close_db(db).unwrap();
    }
    for (_, p) in &prefixes {
        leere_prefix(&ep, &c.bucket, p).await;
    }
}
