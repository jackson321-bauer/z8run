//! S1 (d)(e): WAL-Snapshot, Restart zieht nur fehlende WALs, Epochen lückenlos.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn d_snapshot_und_restart_zieht_nur_fehlenden_schwanz() {
    let base = temp_base("d");
    let storage = base.join("shared-storage");
    let node = node_mit_limit(64);
    node.open_db(
        "db-d",
        &master(),
        cluster_mit_storage("c1", &base.join("lokal-a"), &storage),
    )
    .await
    .unwrap();
    node.reserve("db-d", "s").unwrap();

    // 64 Writes gesamt (1x CREATE + 63x INSERT) -> Snapshot bei WAL 64.
    write(&node, "db-d", "CREATE TABLE t (x INTEGER)", vec![]).await;
    for i in 0..63 {
        write(&node, "db-d", "INSERT INTO t VALUES (?1)", vec![json!(i)]).await;
    }
    let st = node.status(Some("db-d")).unwrap().remove(0);
    assert_eq!(st.wal_stand, 64);
    assert!(st.snapshots >= 1, "kein Snapshot nach 64 WALs");

    // Drei weitere WALs NACH dem Snapshot (65..67).
    for i in 63..66 {
        write(&node, "db-d", "INSERT INTO t VALUES (?1)", vec![json!(i)]).await;
    }
    node.close_db("db-d").unwrap();

    // Neuer Knoten, gleicher Storage, FRISCHES lokales Verzeichnis.
    let node2 = node_mit_limit(64);
    let st2 = node2
        .open_db(
            "db-d",
            &master(),
            cluster_mit_storage("c1", &base.join("lokal-b"), &storage),
        )
        .await
        .unwrap();
    assert!(st2.restored_from_snapshot, "kein Snapshot-Restore");
    assert_eq!(st2.wal_stand, 67);
    assert_eq!(
        st2.remote_wal_downloaded, 3,
        "nur die 3 fehlenden WALs nach dem Snapshot dürfen geladen werden"
    );
    let q = node2.query("db-d", "SELECT count(*) FROM t", &[]).unwrap();
    assert_eq!(q.rows[0][0].as_i64().unwrap(), 66);

    // Wiederöffnen mit gültigem lokalem Stand: 0 Downloads.
    node2.close_db("db-d").unwrap();
    let st3 = node2
        .open_db(
            "db-d",
            &master(),
            cluster_mit_storage("c1", &base.join("lokal-b"), &storage),
        )
        .await
        .unwrap();
    assert_eq!(st3.remote_wal_downloaded, 0);
}

#[tokio::test]
async fn e_zeilen_epochen_lueckenlos_und_hash_kette() {
    let base = temp_base("e");
    let node = node_mit_limit(1000);
    node.open_db("db-e", &master(), cluster("c1", &base))
        .await
        .unwrap();
    node.reserve("db-e", "s").unwrap();
    write(&node, "db-e", "CREATE TABLE t (x INTEGER)", vec![]).await;
    for i in 0..63 {
        write(&node, "db-e", "INSERT INTO t VALUES (?1)", vec![json!(i)]).await;
    }
    let q = node
        .query(
            "db-e",
            "SELECT min(nr), max(nr), count(*) FROM _z8_line_epochs",
            &[],
        )
        .unwrap();
    assert_eq!(q.rows[0][0].as_i64().unwrap(), 1);
    assert_eq!(q.rows[0][1].as_i64().unwrap(), 64);
    assert_eq!(q.rows[0][2].as_i64().unwrap(), 64);

    // Hash-Kette lückenlos: jedes prev_hash == hash des Vorgängers.
    let dir = base.join("c1").join("db-e").join("wal");
    let mut prev = String::new();
    for nr in 1..=64u64 {
        let raw = std::fs::read(dir.join(format!("{nr:08}.json"))).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["nr"].as_u64().unwrap(), nr);
        assert_eq!(v["prev_hash"].as_str().unwrap(), prev, "Kette bei {nr}");
        prev = v["hash"].as_str().unwrap().to_string();
    }
}

#[tokio::test]
async fn e2_deckel_blockiert_zu_lange_und_binæres_sql() {
    let base = temp_base("e2");
    let node = node_mit_limit(1000);
    node.open_db("db-e2", &master(), cluster("c1", &base))
        .await
        .unwrap();
    node.reserve("db-e2", "s").unwrap();
    let lang = "SELECT 1;\n".repeat(206);
    let e = node.write("db-e2", "s", &lang, vec![]).await.unwrap_err();
    assert_eq!(e.code, "DECKEL");
    let e = node.write("db-e2", "s", "SELECT 1\0", vec![]).await.unwrap_err();
    assert_eq!(e.code, "DECKEL");
}
