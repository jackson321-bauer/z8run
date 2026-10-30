//! Regressionen aus dem Zero-Kontext-Audit (BF-1/BF-2):
//! keine WAL-Doppelanwendung nach stale state.json; fehlgeschlagenes SQL
//! hinterlässt kein Cloud-WAL.

mod common;

use common::*;
use serde_json::json;
use std::sync::Arc;
use z8run_core::dbnode::types::Adapter;
use z8run_core::dbnode::DummyBackend;

#[tokio::test]
async fn bf1_stale_state_wendet_wal_nicht_doppelt_an() {
    let base = temp_base("bf1");
    let dbn = node();
    dbn.open_db("db-bf1", &master(), cluster("c1", &base))
        .await
        .unwrap();
    dbn.reserve("db-bf1", "s").unwrap();
    write(&dbn, "db-bf1", "CREATE TABLE t (x INTEGER)", vec![]).await;
    write(&dbn, "db-bf1", "INSERT INTO t VALUES (1)", vec![]).await;
    assert_eq!(
        dbn.query("db-bf1", "SELECT count(*) FROM t", &[]).unwrap().rows[0][0]
            .as_i64()
            .unwrap(),
        1
    );
    dbn.close_db("db-bf1").unwrap();

    // Crash-Simulation: state.json bleibt auf WAL 1 stehen (Commit für WAL 2
    // war bereits lokal, Persist ging verloren).
    let state_pfad = base.join("c1").join("db-bf1").join("state.json");
    let mut st: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_pfad).unwrap()).unwrap();
    st["last_wal"] = json!(1);
    st["next_nr"] = json!(2);
    std::fs::write(&state_pfad, serde_json::to_vec(&st).unwrap()).unwrap();

    let dbn2 = node();
    dbn2
        .open_db("db-bf1", &master(), cluster("c1", &base))
        .await
        .unwrap();
    let n = dbn2
        .query("db-bf1", "SELECT count(*) FROM t", &[])
        .unwrap();
    assert_eq!(
        n.rows[0][0].as_i64().unwrap(),
        1,
        "WAL 2 wurde doppelt angewandt"
    );
}

#[tokio::test]
async fn bf2_fehlgeschlagenes_sql_hinterlaesst_kein_cloud_wal() {
    let base = temp_base("bf2");
    let storage = Arc::new(DummyBackend::new());
    let cluster = z8run_core::dbnode::types::ClusterConfig {
        cluster_id: "dummy".into(),
        local_dir: base.clone(),
        adapter: Adapter::Fs {
            root: base.join("unused").to_string_lossy().to_string(),
        },
    };
    let dbn = node();
    dbn.open_db_with_storage("db-bf2", &master(), cluster.clone(), storage.clone())
        .await
        .unwrap();
    dbn.reserve("db-bf2", "s").unwrap();
    dbn.write("db-bf2", "s", "CREATE TABLE t (x INTEGER)", vec![])
        .await
        .unwrap();
    let e = dbn
        .write(
            "db-bf2",
            "s",
            "INSERT INTO missing_table VALUES (1)",
            vec![],
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, "SQLITE");
    let keys = storage.keys();
    assert!(
        !keys.iter().any(|k| k.contains("/wal/db-bf2/00000002.json")),
        "Cloud-WAL für fehlgeschlagenes SQL: {keys:?}"
    );
    assert_eq!(
        dbn.status(Some("db-bf2")).unwrap().remove(0).wal_stand,
        1
    );
    dbn.close_db("db-bf2").unwrap();

    // Reopen darf nicht an einem toten Cloud-WAL scheitern.
    let dbn2 = node();
    dbn2
        .open_db_with_storage("db-bf2", &master(), cluster, storage)
        .await
        .expect("Reopen nach fehlgeschlagenem SQL");
}
