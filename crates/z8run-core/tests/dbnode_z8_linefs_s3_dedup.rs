//! S3 (c)-(f): Content-Dedup mit refcount, Loesch-Reihenfolge, Race+GC,
//! streamende Hash-Berechnung (RSS flach).

mod common;

use common::*;
use std::path::Path;
use z8run_core::dbnode::DbNode;

fn backend_objekte(base: &Path, db: &str) -> Vec<String> {
    let dir = base.join("storage").join("blobs").join(db);
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                out.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    out
}

fn alle_dateien(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(alle_dateien(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn refcount(node: &DbNode, db: &str, sha: &str) -> Option<i64> {
    let q = node.query(db, "SELECT refcount FROM linefs_blobhash WHERE sha256=?1", &[sha.into()]).unwrap();
    q.rows.first().and_then(|r| r[0].as_i64())
}

#[tokio::test]
async fn c_d_dedup_ein_objekt_zwei_metas_und_loeschen() {
    let base = temp_base("linefs-s3-dedup");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let data = vec![0xABu8; 10 * 1024 * 1024];
    let m1 = node.blob_put_bytes("d", "s", "o", "a.bin", "application/octet-stream", &data).await.unwrap();
    let m2 = node.blob_put_bytes("d", "s", "o", "b.bin", "application/octet-stream", &data).await.unwrap();
    assert_eq!(m1.sha256_klartext, m2.sha256_klartext);
    assert_eq!(m1.storage_uri, m2.storage_uri, "EIN Backend-Objekt");
    assert_ne!(m1.blob_id, m2.blob_id, "zwei Metazeilen");
    let list = node.blob_list("d").unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(backend_objekte(&base, "d").len(), 1);
    assert_eq!(refcount(&node, "d", &m1.sha256_klartext), Some(2));

    // delete einer: refcount 1, Objekt bleibt, andere weiter lesbar.
    node.blob_delete("d", "s", &m1.blob_id).await.unwrap();
    assert_eq!(refcount(&node, "d", &m1.sha256_klartext), Some(1));
    assert_eq!(node.blob_list("d").unwrap().len(), 1);
    assert_eq!(backend_objekte(&base, "d").len(), 1);
    assert_eq!(node.blob_get_bytes("d", &m2.blob_id).await.unwrap(), data);

    // delete der anderen: Objekt weg, Hash-Zeile weg.
    node.blob_delete("d", "s", &m2.blob_id).await.unwrap();
    assert_eq!(refcount(&node, "d", &m1.sha256_klartext), None);
    assert!(node.blob_list("d").unwrap().is_empty());
    assert!(alle_dateien(&base.join("storage").join("blobs").join("d")).is_empty(), "Backend list leer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e_race_zwei_puts_orphan_gc_rest_null() {
    let base = temp_base("linefs-s3-race");
    let node = std::sync::Arc::new(node());
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let data = vec![0xCDu8; 16 * 1024 * 1024];
    let n1 = node.clone();
    let d1 = data.clone();
    let n2 = node.clone();
    let d2 = data.clone();
    let a = tokio::spawn(async move {
        n1.blob_put_bytes("d", "s", "o", "a.bin", "application/octet-stream", &d1).await
    });
    let b = tokio::spawn(async move {
        n2.blob_put_bytes("d", "s", "o", "b.bin", "application/octet-stream", &d2).await
    });
    let (ra, rb) = tokio::join!(a, b);
    ra.unwrap().unwrap();
    rb.unwrap().unwrap();
    let geloescht = node.blob_gc("d").await.unwrap();
    // Nach GC darf KEIN Orphan mehr im Backend liegen.
    let list = node.blob_list("d").unwrap();
    let bekannt: std::collections::HashSet<String> = list.iter().map(|m| m.storage_uri.clone()).collect();
    let mut orphane = 0;
    for p in alle_dateien(&base.join("storage").join("blobs").join("d")) {
        let rel = p.strip_prefix(base.join("storage")).unwrap().to_string_lossy().replace('\\', "/");
        let uri = rel.rsplit_once('/').map(|(a, _)| a.to_string()).unwrap_or(rel);
        if !bekannt.contains(&uri) { orphane += 1; }
    }
    assert_eq!(orphane, 0, "GC-Beweis rest=0");
    for m in &list {
        assert_eq!(node.blob_get_bytes("d", &m.blob_id).await.unwrap(), data);
    }
    println!("RACE metas={} gc_entfernt={}", list.len(), geloescht.len());
    assert!(!geloescht.is_empty(), "Race muss einen Orphan erzeugen (Upload parallel)");
}
