//! S1 (c): 2 DBs parallel schreiben, dritte/​gleiche DB parallel lesen.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn c_zwei_dbs_parallel_schreiben_dritte_parallel_lesen() {
    let base = temp_base("c");
    let node = node();
    for (id, cl) in [("db1", "c1"), ("db2", "c2"), ("db3", "c3")] {
        node.open_db(id, &master(), cluster(cl, &base)).await.unwrap();
        node.reserve(id, "s").unwrap();
    }
    for id in ["db1", "db2", "db3"] {
        write(&node, id, "CREATE TABLE t (x INTEGER)", vec![]).await;
    }

    let w1 = node.write("db1", "s", "INSERT INTO t VALUES (?1)", vec![json!(1)]);
    let w2 = node.write("db2", "s", "INSERT INTO t VALUES (?1)", vec![json!(2)]);
    let q3 = async { node.query("db3", "SELECT count(*) FROM t", &[]) };
    let (r1, r2, r3) = tokio::join!(w1, w2, q3);
    assert_eq!(r1.unwrap().wal_nr, 2);
    assert_eq!(r2.unwrap().wal_nr, 2);
    assert_eq!(r3.unwrap().rows[0][0].as_i64().unwrap(), 0);

    // Lesen derselben DB parallel zum Schreiben (readonly, eigene Verbindung).
    let w = node.write("db1", "s", "INSERT INTO t VALUES (?1)", vec![json!(3)]);
    let q = async { node.query("db1", "SELECT count(*) FROM t", &[]) };
    let (w, q) = tokio::join!(w, q);
    assert!(w.is_ok(), "write parallel zu read: {w:?}");
    assert!(q.is_ok(), "read parallel zu write: {q:?}");
    let n = q.unwrap().rows[0][0].as_i64().unwrap();
    assert!(n == 1 || n == 2, "count={n}");

    // Dritte DB bleibt unabhängig.
    assert_eq!(
        node.query("db2", "SELECT count(*) FROM t", &[]).unwrap().rows[0][0]
            .as_i64()
            .unwrap(),
        1
    );
}
