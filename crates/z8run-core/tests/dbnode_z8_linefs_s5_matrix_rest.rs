//! S5: direkte Laufzeitbeweise für lesen/suchen/ersetzen/speichern,
//! Ordner-Umbenennen und Ordner/Datei-Namenskollisionen.

mod common;

use common::*;
use serde_json::Value;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, s: &str, a: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: "d".into(), session_id: s.into(), aktion: a })
        .await
        .unwrap()
}

async fn err(node: &DbNode, s: &str, a: LinefsAktion) -> z8run_core::dbnode::types::DbError {
    node.linefs(LinefsRequest { db_id: "d".into(), session_id: s.into(), aktion: a })
        .await.unwrap_err()
}

#[tokio::test]
async fn lesen_suchen_ersetzen_speichern_und_ordner_umbenennen() {
    let base = temp_base("linefs-s5-rest");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    lf(&node, "s", LinefsAktion::LinefsAnlegen {
        name: "m.txt".into(), art: "code".into(), text: "eins\nzwei\ndrei".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    lf(&node, "s", LinefsAktion::LinefsOeffnen { pfad: "m.txt".into() }).await;

    let lesen = lf(&node, "s", LinefsAktion::LinefsLesen {
        pfad: String::new(), von: Some(2), bis: Some(3),
    }).await;
    let zeilen = lesen["zeilen"].as_array().unwrap();
    assert_eq!(zeilen.len(), 2);
    assert_eq!(zeilen[0]["inhalt"], "zwei");
    assert_eq!(zeilen[1]["inhalt"], "drei");

    let suche = lf(&node, "s", LinefsAktion::LinefsSuchen {
        muster: "wei".into(), pfad: String::new(),
    }).await;
    assert_eq!(suche["treffer"][0]["nr"], 2);

    let ers = lf(&node, "s", LinefsAktion::LinefsErsetzen {
        suche: "zwei".into(), ersatz: "ZWEI".into(),
    }).await;
    assert_eq!(ers["ersetzt"], 1);
    assert_eq!(lf(&node, "s", LinefsAktion::LinefsSpeichern).await["ok"], true);
    let c = lf(&node, "s", LinefsAktion::LinefsSchliessen).await;
    assert_eq!(c["fassung"], 2);
    let r = lf(&node, "s", LinefsAktion::LinefsRendere { pfad: "m.txt".into() }).await;
    assert_eq!(r["text"], "eins\nZWEI\ndrei");

    let o = lf(&node, "s", LinefsAktion::OrdnerAnlegen { eltern_id: 0, name: "alt".into() }).await;
    let id = o["id"].as_i64().unwrap();
    lf(&node, "s", LinefsAktion::OrdnerUmbenennen { id, name: "neu".into() }).await;
    let liste = lf(&node, "s", LinefsAktion::OrdnerListen { eltern_id: 0 }).await;
    assert!(liste["eintraege"].as_array().unwrap().iter().any(|e| e["name"] == "neu"));

    // Ordner/Datei-Namenskollision in derselben Ebene = Fehler.
    let e = err(&node, "s", LinefsAktion::LinefsAnlegen {
        name: "neu".into(), art: "code".into(), text: "x".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    assert!(e.message.contains("Ordner belegt"), "{e:?}");
    lf(&node, "s", LinefsAktion::LinefsAnlegen {
        name: "datei-name".into(), art: "code".into(), text: "x".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    let e = err(&node, "s", LinefsAktion::OrdnerAnlegen { eltern_id: 0, name: "datei-name".into() }).await;
    assert!(e.message.contains("Datei belegt"), "{e:?}");
}
