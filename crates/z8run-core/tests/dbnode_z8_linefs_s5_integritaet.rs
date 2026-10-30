//! S5/G8: Integritaets-Guard auch an Umbenennen und Binaer-Uebergaengen
//! (verwaiste Datei nach externem Ordner-Loeschen -> klarer Fehler).

mod common;

use common::*;
use serde_json::json;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, a: LinefsAktion) -> serde_json::Value {
    node.linefs(LinefsRequest { db_id: "d".into(), session_id: "s".into(), aktion: a })
        .await.unwrap()
}

async fn err(node: &DbNode, a: LinefsAktion) -> z8run_core::dbnode::types::DbError {
    node.linefs(LinefsRequest { db_id: "d".into(), session_id: "s".into(), aktion: a })
        .await.unwrap_err()
}

#[tokio::test]
async fn integritaet_blockt_umbenennen_und_binaer_uebergang() {
    let base = temp_base("linefs-s5-int");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let x = lf(&node, LinefsAktion::OrdnerAnlegen { eltern_id: 0, name: "x".into() }).await;
    let y = lf(&node, LinefsAktion::OrdnerAnlegen { eltern_id: 0, name: "y".into() }).await;
    lf(&node, LinefsAktion::LinefsAnlegen {
        name: "root.txt".into(), art: "code".into(), text: "a".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    lf(&node, LinefsAktion::LinefsAnlegen {
        name: "lost.txt".into(), art: "code".into(), text: "b".into(),
        urheber: "ki".into(), ordner_id: Some(x["id"].as_i64().unwrap()),
    }).await;
    // externer Eingriff: Ordner weg -> Datei verwaist.
    node.write("d", "s", "DELETE FROM ordner WHERE id=?1",
        vec![json!(x["id"].as_i64().unwrap())]).await.unwrap();

    let e = err(&node, LinefsAktion::LinefsUmbenennen {
        pfad: "root.txt".into(), neu: "root2.txt".into(),
    }).await;
    assert!(e.message.contains("ORDNER-INTEGRITAET"), "umbenennen: {e:?}");

    let e = err(&node, LinefsAktion::LinefsUebergangZuBinaer {
        pfad: "root.txt".into(), name: "root.bin".into(),
        mime: "application/octet-stream".into(),
    }).await;
    assert!(e.message.contains("ORDNER-INTEGRITAET"), "binaer: {e:?}");

    let e = err(&node, LinefsAktion::OrdnerUmbenennen {
        id: y["id"].as_i64().unwrap(), name: "y2".into(),
    }).await;
    assert!(e.message.contains("ORDNER-INTEGRITAET"), "ordner: {e:?}");
}
