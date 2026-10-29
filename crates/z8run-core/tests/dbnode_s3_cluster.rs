//! S3: Multi-Cluster-Beweis gegen echten DanubeData-S3 (3 Test-Prefixe)
//! + FsBackend. KEINE Produktiv-Prefixe, keine Keys im Log.

mod common;

use common::*;
use kv_store::s3::S3Endpoint;
use serde::Deserialize;
use serde_json::json;
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

async fn leere_prefix(ep: &S3Endpoint, bucket: &str, prefix: &str) {
    let objs = ep.list_objects(bucket, &format!("{prefix}/")).await.unwrap();
    for o in &objs {
        ep.delete_object(bucket, &o.key).await.unwrap();
    }
    let rest = ep.list_objects(bucket, &format!("{prefix}/")).await.unwrap();
    assert!(rest.is_empty(), "Prefix {prefix} nicht leer: {} Objekte", rest.len());
    println!("CLEANUP prefix={prefix} geloescht={} rest={}", objs.len(), rest.len());
}

#[tokio::test]
async fn drei_cluster_parallel_write_und_read_mit_wal_upload() {
    let c = cfg();
    let ep = S3Endpoint {
        host: c.host.clone(),
        region: c.region.clone(),
        access_key: c.access_key.clone(),
        secret_key: c.secret_key.clone(),
    };
    let base = temp_base("s3-multi");
    let prefixes = [
        ("c-a", "dbs/test-a"),
        ("c-b", "dbs/test-b"),
        ("c-c", "dbs/test-c"),
    ];
    for (_, p) in &prefixes {
        leere_prefix(&ep, &c.bucket, p).await;
    }

    let node = node();
    node.open_db("ta1", &master(), cluster_s3("c-a", &base.join("a"), &c, "dbs/test-a"))
        .await
        .unwrap();
    node.open_db("ta2", &master(), cluster_s3("c-a", &base.join("a"), &c, "dbs/test-a"))
        .await
        .unwrap();
    node.open_db("tb1", &master(), cluster_s3("c-b", &base.join("b"), &c, "dbs/test-b"))
        .await
        .unwrap();
    node.open_db("tc1", &master(), cluster_s3("c-c", &base.join("c"), &c, "dbs/test-c"))
        .await
        .unwrap();
    for (db, sess) in [("ta1", "sa1"), ("ta2", "sa2"), ("tb1", "sb1"), ("tc1", "sc1")] {
        node.reserve(db, sess).unwrap();
        node.write(db, sess, "CREATE TABLE t (x INTEGER)", vec![])
            .await
            .unwrap();
    }
    // 2 DBs auf VERSCHIEDENEN Clustern parallel schreiben, 3. lesend.
    let w1 = node.write("ta1", "sa1", "INSERT INTO t VALUES (?1)", vec![json!(1)]);
    let w2 = node.write("tb1", "sb1", "INSERT INTO t VALUES (?1)", vec![json!(2)]);
    let r = async { node.query("tc1", "SELECT count(*) FROM t", &[]) };
    let (w1, w2, r) = tokio::join!(w1, w2, r);
    assert_eq!(w1.unwrap().wal_nr, 2);
    assert_eq!(w2.unwrap().wal_nr, 2);
    assert_eq!(r.unwrap().rows[0][0].as_i64().unwrap(), 0);
    // Zweite DB auf Cluster A ebenfalls schreiben.
    node.write("ta2", "sa2", "INSERT INTO t VALUES (?1)", vec![json!(3)])
        .await
        .unwrap();

    // WAL-Objekte je Cluster sichtbar (S3-List je Prefix).
    let mut keys: Vec<(String, usize)> = Vec::new();
    for (_, p) in &prefixes {
        let objs = ep.list_objects(&c.bucket, &format!("{p}/wal/")).await.unwrap();
        println!("S3-LIST prefix={p} wal_objekte={}", objs.len());
        for o in &objs {
            println!("  S3-KEY {}", o.key);
        }
        assert!(!objs.is_empty(), "keine WAL-Uploads unter {p}");
        keys.push((p.to_string(), objs.len()));
    }
    assert_eq!(keys.len(), 3);

    let st = node.status(None).unwrap();
    assert_eq!(st.len(), 4);
    for s in &st {
        assert!(s.wal_stand >= 1, "{} wal_stand={}", s.db_id, s.wal_stand);
    }

    for db in ["ta1", "ta2", "tb1", "tc1"] {
        node.close_db(db).unwrap();
    }
    for (_, p) in &prefixes {
        leere_prefix(&ep, &c.bucket, p).await;
    }
}
