//! S4: Storage-Ausfall — Write bleibt lokal erhalten (kein Datenverlust),
//! wal-sync holt nach, sobald der Storage wieder erreichbar ist.

mod common;

use common::*;
use serde_json::json;
use std::sync::Arc;
use z8run_core::dbnode::types::Adapter;
use z8run_core::dbnode::DummyBackend;

#[tokio::test]
async fn write_ueberlebt_storage_ausfall_und_sync_holt_nach() {
    let base = temp_base("s4-offline");
    let storage = Arc::new(DummyBackend::new());
    let cluster = z8run_core::dbnode::types::ClusterConfig {
        cluster_id: "dummy".into(),
        local_dir: base.clone(),
        adapter: Adapter::Fs {
            root: base.join("unused").to_string_lossy().to_string(),
        },
    };
    let node = node();
    node.open_db_with_storage("db-off", &master(), cluster, storage.clone())
        .await
        .unwrap();
    node.reserve("db-off", "s").unwrap();
    node.write("db-off", "s", "CREATE TABLE t (x INTEGER)", vec![])
        .await
        .unwrap();
    let before = storage.keys();
    assert!(before.iter().any(|k| k.starts_with("wal/db-off/")));

    // S3/Storage fällt aus.
    storage.set_online(false);
    node.write("db-off", "s", "INSERT INTO t VALUES (?1)", vec![json!(1)])
        .await
        .expect("Write muss auch ohne Storage lokal gelingen");
    let st = node.status(Some("db-off")).unwrap().remove(0);
    assert_eq!(st.wal_stand, 2);
    assert_eq!(st.wal_pending, 1, "WAL muss lokal pending sein");
    let q = node.query("db-off", "SELECT count(*) FROM t", &[]).unwrap();
    assert_eq!(q.rows[0][0].as_i64().unwrap(), 1);

    // Storage wieder da -> wal-sync holt nach.
    storage.set_online(true);
    let p = node.wal_sync("db-off").await.unwrap();
    assert_eq!(p.wal_synced, 2);
    assert_eq!(p.wal_pending, 0);
    assert!(storage
        .keys()
        .iter()
        .any(|k| k == "wal/db-off/00000002.json"));
    let q = node.query("db-off", "SELECT count(*) FROM t", &[]).unwrap();
    assert_eq!(q.rows[0][0].as_i64().unwrap(), 1);
    println!("OFFLINE-BEWEIS wal_stand=2 synced=2 pending=0 rows=1");
}
