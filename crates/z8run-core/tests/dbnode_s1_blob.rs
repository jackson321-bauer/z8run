//! S1 (a)(b)(c)(d)(f): Blob roundtrip, Chiffre im Backend, Delete+Orphan-GC,
//! Masterkey-Zwang, Meta-Zeile mit lückenloser WAL-Epoche.

mod common;

use common::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use z8run_core::dbnode::{DbNode, DummyBackend, StorageBackend};

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[tokio::test]
async fn a_roundtrip_1kb_und_10mb() {
    let base = temp_base("blob-a");
    let node = node();
    node.open_db("db-a", &master(), cluster("c1", &base)).await.unwrap();
    node.reserve("db-a", "s").unwrap();

    let klein = vec![0xABu8; 1024];
    let m1 = node
        .blob_put_bytes("db-a", "s", "jason", "klein.bin", "application/octet-stream", &klein)
        .await
        .unwrap();
    assert_eq!(m1.groesse, 1024);
    assert_eq!(node.blob_get_bytes("db-a", &m1.blob_id).await.unwrap(), klein);

    let gross = vec![0x5Cu8; 10 * 1024 * 1024];
    let m2 = node
        .blob_put_bytes("db-a", "s", "jason", "gross.bin", "application/octet-stream", &gross)
        .await
        .unwrap();
    let out = node.blob_get_bytes("db-a", &m2.blob_id).await.unwrap();
    assert_eq!(sha(&gross), sha(&out), "10MB-SHA256");
    assert_eq!(sha(&gross), m2.sha256_klartext);
}

#[tokio::test]
async fn b_backend_objekt_ist_chiffre() {
    let base = temp_base("blob-b");
    let node = node();
    let storage = Arc::new(DummyBackend::new());
    node.open_db_with_storage("db-b", &master(), cluster("c1", &base), storage.clone())
        .await
        .unwrap();
    node.reserve("db-b", "s").unwrap();
    let plain = b"KLARTEXT-BEWEIS-z8-dbblob-1234567890";
    let m = node
        .blob_put_bytes("db-b", "s", "o", "x.txt", "text/plain", plain)
        .await
        .unwrap();
    let keys = storage.keys();
    assert!(!keys.is_empty(), "kein Storage-Objekt");
    let roh = storage.read(&keys[0]).await.unwrap().unwrap();
    assert_ne!(roh.as_slice(), plain, "Backend sieht Klartext!");
    assert!(!roh.windows(plain.len()).any(|w| w == plain), "Klartext im Chiffre");
    assert_eq!(node.blob_get_bytes("db-b", &m.blob_id).await.unwrap(), plain);
}

#[tokio::test]
async fn c_delete_reihenfolge_und_orphan_gc() {
    let base = temp_base("blob-c");
    let node = node();
    let storage = Arc::new(DummyBackend::new());
    node.open_db_with_storage("db-c", &master(), cluster("c1", &base), storage.clone())
        .await
        .unwrap();
    node.reserve("db-c", "s").unwrap();
    let m = node
        .blob_put_bytes("db-c", "s", "o", "weg.bin", "application/octet-stream", b"123456")
        .await
        .unwrap();
    assert!(!storage.list("blobs/db-c/").await.unwrap().is_empty());
    node.blob_delete("db-c", "s", &m.blob_id).await.unwrap();
    assert!(node.blob_list("db-c").unwrap().is_empty(), "Meta-Zeile blieb");
    assert!(storage.list("blobs/db-c/").await.unwrap().is_empty(), "Backend-Objekt blieb");

    // Orphan (Crash zwischen Meta-Delete und Backend-Delete) ist GC-bar.
    storage
        .write("blobs/db-c/orphan-1/00000000.part", b"chiffre-rest")
        .await
        .unwrap();
    let deleted = node.blob_gc("db-c").await.unwrap();
    assert_eq!(deleted.len(), 1);
    assert!(storage.list("blobs/db-c/").await.unwrap().is_empty(), "Orphan nicht entfernt");
}

#[tokio::test]
async fn d_ohne_masterkey_kein_oeffnen() {
    let base = temp_base("blob-d");
    let node = node();
    node.open_db("db-d", &master(), cluster("c1", &base)).await.unwrap();
    node.reserve("db-d", "s").unwrap();
    node.blob_put_bytes("db-d", "s", "o", "x", "application/octet-stream", b"geheim")
        .await
        .unwrap();

    let node2 = DbNode::new(z8run_core::dbnode::types::DbNodeConfig::default());
    let falsch = b"falscher-master-key-000000000000".to_vec();
    let err = node2
        .open_db("db-d", &falsch, cluster("c1", &base))
        .await
        .unwrap_err();
    assert!(!err.message.is_empty());
}

#[tokio::test]
async fn f_wal_epoche_enthaelt_meta_zeile() {
    let base = temp_base("blob-f");
    let node = node();
    let storage = Arc::new(DummyBackend::new());
    node.open_db_with_storage("db-f", &master(), cluster("c1", &base), storage.clone())
        .await
        .unwrap();
    node.reserve("db-f", "s").unwrap();
    let m = node
        .blob_put_bytes("db-f", "s", "o", "e.bin", "application/octet-stream", b"epoche")
        .await
        .unwrap();
    let wal = storage.list("wal/db-f/").await.unwrap();
    assert_eq!(wal.len(), 1, "genau ein WAL-Objekt");
    let q = node
        .query("db-f", "SELECT count(*), max(nr) FROM _z8_line_epochs", &[])
        .unwrap();
    assert_eq!(q.rows[0][0].as_i64(), Some(1));
    assert_eq!(q.rows[0][1].as_i64(), Some(1));
    let listed = node.blob_list("db-f").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].epoch, 1, "Meta-Zeile trägt die WAL-Epoche");
    assert_eq!(listed[0].blob_id, m.blob_id);
}
