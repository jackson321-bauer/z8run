//! S1: Natives Nachrichten-Interface über lokalen mpsc-Kanal (kein HTTP).

mod common;

use common::*;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;
use z8run_core::dbnode::{serve, DbNodeCommand, DbNodeEvent};

#[tokio::test]
async fn nachrichten_interface_ueber_kanal() {
    let base = temp_base("msg");
    let node = Arc::new(node());
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (ev_tx, mut ev_rx) = mpsc::channel(16);
    let server = tokio::spawn(serve(node.clone(), cmd_rx, ev_tx));

    use base64::Engine;
    let master_b64 = base64::engine::general_purpose::STANDARD.encode(master());
    let cmds = vec![
        DbNodeCommand::OpenDb {
            db_id: "db-m".into(),
            master_key_b64: master_b64,
            cluster: cluster("c1", &base),
        },
        DbNodeCommand::Reserve {
            db_id: "db-m".into(),
            session_id: "proxy-session".into(),
        },
        DbNodeCommand::Write {
            db_id: "db-m".into(),
            session_id: "proxy-session".into(),
            sql: "CREATE TABLE t (x INTEGER)".into(),
            params: vec![],
        },
        DbNodeCommand::Query {
            db_id: "db-m".into(),
            sql: "SELECT count(*) FROM t".into(),
            params: vec![],
            readonly: true,
        },
        DbNodeCommand::Status { db_id: None },
    ];
    for c in cmds {
        cmd_tx.send(c).await.unwrap();
    }
    drop(cmd_tx);

    let mut seen = Vec::new();
    while let Some(ev) = ev_rx.recv().await {
        seen.push(ev);
    }
    server.await.unwrap();
    assert_eq!(seen.len(), 5, "Events: {seen:?}");
    assert!(matches!(&seen[0], DbNodeEvent::Ok { op, .. } if op == "open"));
    assert!(matches!(&seen[1], DbNodeEvent::Ok { op, .. } if op == "reserve"));
    assert!(matches!(&seen[2], DbNodeEvent::WriteOk { .. }));
    assert!(matches!(&seen[3], DbNodeEvent::Rows { .. }));
    assert!(matches!(&seen[4], DbNodeEvent::Status { .. }));

    if let DbNodeEvent::Rows { outcome, .. } = &seen[3] {
        assert_eq!(outcome.rows[0][0].as_i64().unwrap(), 0);
    }
    // Query mit Parameter beweist, dass Params das Interface passieren.
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (ev_tx, mut ev_rx) = mpsc::channel(4);
    let server = tokio::spawn(serve(node.clone(), cmd_rx, ev_tx));
    cmd_tx
        .send(DbNodeCommand::Query {
            db_id: "db-m".into(),
            sql: "SELECT ?1".into(),
            params: vec![json!("durchgereicht")],
            readonly: true,
        })
        .await
        .unwrap();
    drop(cmd_tx);
    let ev = ev_rx.recv().await.unwrap();
    server.await.unwrap();
    if let DbNodeEvent::Rows { outcome, .. } = ev {
        assert_eq!(outcome.rows[0][0].as_str().unwrap(), "durchgereicht");
    } else {
        panic!("kein Rows-Event: {ev:?}");
    }
}
