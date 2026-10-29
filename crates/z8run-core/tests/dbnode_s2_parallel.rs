//! S2: db-query readonly parallel zu db-write (Node-Ebene, gleiche DB).

mod common;

use common::*;
use serde_json::{json, Value};
use uuid::Uuid;
use z8run_core::engine::NodeExecutorFactory;
use z8run_core::message::FlowMessage;
use z8run_core::nodes::dbnode_common::engine;
use z8run_core::nodes::dbnode_query::{DbQueryNodeFactory, DbWriteNodeFactory};

fn msg(payload: Value) -> FlowMessage {
    FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7())
}

#[tokio::test]
async fn db_query_readonly_parallel_zum_write() {
    let base = temp_base("s2-par");
    let cluster = cluster("c1", &base);
    let e = engine();
    e.open_db("db-par", &master(), cluster).await.unwrap();
    e.reserve("db-par", "s").unwrap();
    e.write("db-par", "s", "CREATE TABLE t (x INTEGER)", vec![])
        .await
        .unwrap();
    e.release("db-par", "s").unwrap();

    let wfac = DbWriteNodeFactory;
    let qfac = DbQueryNodeFactory;
    let w = wfac
        .create(json!({"dbId": "db-par", "sql": "INSERT INTO t VALUES (?1)",
                       "paramsPath": "params", "sessionPath": "session_id",
                       "autoReserve": true}))
        .await
        .unwrap();
    let q = qfac
        .create(json!({"dbId": "db-par", "sql": "SELECT count(*) FROM t",
                       "paramsPath": "params"}))
        .await
        .unwrap();

    let (wr, qr) = tokio::join!(
        w.process(msg(json!({"params": [7], "session_id": "node-s"}))),
        q.process(msg(json!({"params": []})))
    );
    let wr = wr.unwrap();
    let qr = qr.unwrap();
    assert_eq!(wr[0].source_port, "output", "write: {:?}", wr[0].payload);
    assert_eq!(qr[0].source_port, "output", "query: {:?}", qr[0].payload);
    let n = qr[0].payload["rows"][0][0].as_i64().unwrap();
    assert!(n == 0 || n == 1, "count={n}");

    let st = e.status(Some("db-par")).unwrap().remove(0);
    assert_eq!(st.reservation, "frei", "auto-reserve muss freigeben");
}
