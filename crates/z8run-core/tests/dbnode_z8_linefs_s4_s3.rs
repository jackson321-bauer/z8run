//! S4: echtes DanubeData-S3 (NEUE Prefixe dbs/test-linefs/, sim2/kronvault
//! unberuehrt). Ordner-Baum + Zeilen-Datei + Dedup-Blobs auf 2 Clustern.
//! Aufraeumen rest=0.

mod common;

use common::*;
use kv_store::s3::S3Endpoint;
use serde::Deserialize;
use serde_json::Value;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::types::{Adapter, ClusterConfig};
use z8run_core::dbnode::DbNode;

#[derive(Deserialize)]
struct S3Cfg { host: String, region: String, access_key: String, secret_key: String, bucket: String }

fn cfg() -> S3Cfg {
    let path = std::env::var("Z8_DBBOX_S3_CONFIG").unwrap_or_else(|_| "/etc/z8run/s3.json".into());
    serde_json::from_slice(&std::fs::read(&path).expect("S3-Config lesbar")).unwrap()
}

fn cluster_s3(id: &str, base: &std::path::Path, c: &S3Cfg, prefix: &str) -> ClusterConfig {
    ClusterConfig {
        cluster_id: id.into(), local_dir: base.into(),
        adapter: Adapter::S3 {
            host: c.host.clone(), region: c.region.clone(),
            access_key: c.access_key.clone(), secret_key: c.secret_key.clone(),
            bucket: c.bucket.clone(), prefix: prefix.into(),
        },
    }
}

async fn leere_prefix(ep: &S3Endpoint, bucket: &str, prefix: &str) {
    let objs = ep.list_objects(bucket, &format!("{prefix}/")).await.unwrap();
    for o in &objs { ep.delete_object(bucket, &o.key).await.unwrap(); }
    let rest = ep.list_objects(bucket, &format!("{prefix}/")).await.unwrap();
    assert!(rest.is_empty(), "Prefix {prefix} nicht leer: {}", rest.len());
    println!("CLEANUP prefix={prefix} geloescht={} rest={}", objs.len(), rest.len());
}

async fn lf(node: &DbNode, db: &str, s: &str, a: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: db.into(), session_id: s.into(), aktion: a }).await.unwrap()
}

#[tokio::test]
async fn s3_linefs_ordner_baum_zeilen_dedup_und_cleanup() {
    let c = cfg();
    let ep = S3Endpoint { host: c.host.clone(), region: c.region.clone(),
        access_key: c.access_key.clone(), secret_key: c.secret_key.clone() };
    let prefixes = [("c-a", "dbs/test-linefs/a"), ("c-b", "dbs/test-linefs/b")];
    for (_, p) in &prefixes { leere_prefix(&ep, &c.bucket, p).await; }

    let base = temp_base("s3-linefs");
    let node = node();
    let dbs = [("lf-a", "c-a", "sa", prefixes[0].1, base.join("a")),
               ("lf-b", "c-b", "sb", prefixes[1].1, base.join("b"))];
    let blobs = vec![0x7Eu8; 2 * 1024 * 1024];
    let mut ids: Vec<(String, String)> = Vec::new();
    for (db, cid, sess, prefix, dir) in &dbs {
        node.open_db(db, &master(), cluster_s3(cid, dir, &c, prefix)).await.unwrap();
        node.reserve(db, sess).unwrap();
        let a = lf(&node, db, sess, LinefsAktion::OrdnerAnlegen { eltern_id: 0, name: "docs".into() }).await;
        let b = lf(&node, db, sess, LinefsAktion::OrdnerAnlegen {
            eltern_id: a["id"].as_i64().unwrap(), name: "projekte".into(),
        }).await;
        lf(&node, db, sess, LinefsAktion::LinefsAnlegen {
            name: "notiz.txt".into(), art: "dokument".into(),
            text: "Zeile1\nZeile2\nZeile3".into(), urheber: "s4".into(),
            ordner_id: Some(b["id"].as_i64().unwrap()),
        }).await;
        lf(&node, db, sess, LinefsAktion::LinefsOeffnen { pfad: "docs/projekte/notiz.txt".into() }).await;
        lf(&node, db, sess, LinefsAktion::LinefsZeileSetzen { nr: 2, inhalt: "Zeile2-S3".into() }).await;
        let commit = lf(&node, db, sess, LinefsAktion::LinefsSchliessen).await;
        assert_eq!(commit["fassung"], 2);
        let rend = lf(&node, db, sess, LinefsAktion::LinefsRendere {
            pfad: "docs/projekte/notiz.txt".into(),
        }).await;
        assert_eq!(rend["text"], "Zeile1\nZeile2-S3\nZeile3");
        let m1 = node.blob_put_bytes(db, sess, "s4", "gleich.bin", "application/octet-stream", &blobs).await.unwrap();
        let m2 = node.blob_put_bytes(db, sess, "s4", "gleich2.bin", "application/octet-stream", &blobs).await.unwrap();
        assert_eq!(m1.storage_uri, m2.storage_uri, "Dedup auf echtem S3");
        let out = node.blob_get_bytes(db, &m1.blob_id).await.unwrap();
        assert_eq!(out, blobs, "{db}: S3-Download");
        ids.push((db.to_string(), m1.blob_id));
        println!("DB_OK db={db} cluster={cid} prefix={prefix} dedup_uri={}", m1.storage_uri);
        let liste = lf(&node, db, sess, LinefsAktion::OrdnerListen { eltern_id: 0 }).await;
        assert_eq!(liste["eintraege"][0]["name"], "docs");
    }
    assert_eq!(ids.len(), 2);
    for (db, _) in &ids { node.close_db(db).unwrap(); }
    for (_, p) in &prefixes { leere_prefix(&ep, &c.bucket, p).await; }
    // Beweis: keine Objekte mehr unter den Test-Prefixen.
    for (_, p) in &prefixes {
        let rest = ep.list_objects(&c.bucket, &format!("{p}/")).await.unwrap();
        assert_eq!(rest.len(), 0, "rest={}", rest.len());
    }
    println!("S3_LINEFS_OK dbs={} prefixes={:?}", ids.len(), prefixes.map(|(_, p)| p));
}
