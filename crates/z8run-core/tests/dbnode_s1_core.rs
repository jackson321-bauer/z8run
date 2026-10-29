//! S1 (a)(b): vec+FTS5 eingebrannt, Reservierungspflicht, Ein-Schreiber.

mod common;

use common::*;
use serde_json::json;
use z8run_core::dbnode::types::DbNodeConfig;

#[tokio::test]
async fn a_open_erstellt_vec0_und_fts5_ohne_load_extension() {
    let base = temp_base("a");
    let node = node();
    node.open_db("db-a", &master(), cluster("c1", &base))
        .await
        .unwrap();
    node.reserve("db-a", "s").unwrap();
    write(&node, "db-a", "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)", vec![]).await;
    write(
        &node,
        "db-a",
        "CREATE VIRTUAL TABLE fts_notes USING fts5(body)",
        vec![],
    )
    .await;
    write(
        &node,
        "db-a",
        "CREATE VIRTUAL TABLE vec_notes USING vec0(embedding float[4])",
        vec![],
    )
    .await;
    write(
        &node,
        "db-a",
        "INSERT INTO fts_notes(body) VALUES (?1)",
        vec![json!("vektorbeweis")],
    )
    .await;

    let v = node.query("db-a", "SELECT vec_version()", &[]).unwrap();
    let version = v.rows[0][0].as_str().unwrap().to_string();
    assert!(version.starts_with('v'), "vec_version={version}");

    let fts = node
        .query(
            "db-a",
            "SELECT count(*) FROM fts_notes WHERE fts_notes MATCH ?1",
            &[json!("vektorbeweis")],
        )
        .unwrap();
    assert_eq!(fts.rows[0][0].as_i64().unwrap(), 1);

    let fts5: String = {
        let r = node
            .query("db-a", "SELECT sqlite_compileoption_used('ENABLE_FTS5')", &[])
            .unwrap();
        r.rows[0][0].to_string()
    };
    assert_eq!(fts5, "1", "FTS5 nicht einkompiliert");
}

#[tokio::test]
async fn b_reservierungspflicht_und_zweite_reservierung() {
    let base = temp_base("b");
    let node = node();
    node.open_db("db-b", &master(), cluster("c1", &base))
        .await
        .unwrap();

    // write ohne Reservierung = FEHLER
    let e = node
        .write("db-b", "nobody", "CREATE TABLE t (x INTEGER)", vec![])
        .await
        .unwrap_err();
    assert_eq!(e.code, "NOT_RESERVED");

    node.reserve("db-b", "s1").unwrap();
    // zweite Reservierung = FEHLER
    assert_eq!(node.reserve("db-b", "s2").unwrap_err().code, "BUSY");

    node.write("db-b", "s1", "CREATE TABLE t (x INTEGER)", vec![]).await.unwrap();
    node.release("db-b", "s1").unwrap();

    // nach release wieder frei -> andere Session darf
    node.reserve("db-b", "s2").unwrap();
    node.write("db-b", "s2", "INSERT INTO t VALUES (42)", vec![]).await.unwrap();
    let q = node.query("db-b", "SELECT x FROM t", &[]).unwrap();
    assert_eq!(q.rows[0][0].as_i64().unwrap(), 42);

    // falscher Besitzer kann nicht freigeben
    assert_eq!(node.release("db-b", "s1").unwrap_err().code, "NOT_OWNER");
}

#[tokio::test]
async fn b2_default_config_ist_flach() {
    let cfg = DbNodeConfig::default();
    assert_eq!(cfg.wal_snapshot_limit, 64);
    assert_eq!(cfg.snapshot_interval.as_secs(), 3600);
}
