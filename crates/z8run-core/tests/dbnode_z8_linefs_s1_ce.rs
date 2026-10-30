//! S1 CE-Spiegel: Faulpelz-DECKEL, Auto-Paging, Zeilenmonster,
//! 50-Fassungs-Kette, Umbenennen nur Mapping.

mod common;

use common::*;
use serde_json::{json, Value};
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, db: &str, s: &str, a: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: db.into(), session_id: s.into(), aktion: a })
        .await
        .unwrap()
}

async fn anlegen(node: &DbNode, db: &str, name: &str, art: &str, text: &str) -> i64 {
    let v = lf(node, db, "s", LinefsAktion::LinefsAnlegen {
        name: name.into(), art: art.into(), text: text.into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    v["datei_id"].as_i64().unwrap()
}

async fn rendere(node: &DbNode, db: &str, pfad: &str) -> String {
    let v = lf(node, db, "s", LinefsAktion::LinefsRendere { pfad: pfad.into() }).await;
    v["text"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn faulpelz_veralteter_stand_wird_abgelehnt() {
    let base = temp_base("linefs-ce-f");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let id = anlegen(&node, "d", "f.txt", "code", "a").await;
    lf(&node, "d", "s", LinefsAktion::LinefsOeffnen { pfad: "f.txt".into() }).await;
    node.write("d", "s", "UPDATE dateien SET fassung = fassung + 1 WHERE datei_id = ?1",
        vec![json!(id)]).await.unwrap();
    lf(&node, "d", "s", LinefsAktion::LinefsZeileSetzen { nr: 1, inhalt: "b".into() }).await;
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsSchliessen,
    }).await.unwrap_err();
    assert!(e.message.contains("veralteter Stand"), "{e:?}");
}

#[tokio::test]
async fn dokument_auto_paging_nahtlos() {
    let base = temp_base("linefs-ce-p");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let text = (1..=300).map(|i| i.to_string()).collect::<Vec<_>>().join("\n");
    anlegen(&node, "d", "d.md", "dokument", &text).await;
    let s = lf(&node, "d", "s", LinefsAktion::LinefsSeiten { pfad: "d.md".into() }).await;
    assert_eq!(s["seiten"].as_array().unwrap().len(), 2);
    assert_eq!(rendere(&node, "d", "d.md").await, text);
}

#[tokio::test]
async fn zeilenmonster_segmente_und_bearbeitung() {
    let base = temp_base("linefs-ce-m");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let monster = "m".repeat(1024 * 1024);
    let text = format!("vor\n{monster}\nnach");
    let id = anlegen(&node, "d", "monster.txt", "code", &text).await;
    let q = node.query("d", "SELECT count(*) FROM zeilen_epochen WHERE datei_id=?1 AND schluessel=2",
        &[json!(id)]).unwrap();
    assert!(q.rows[0][0].as_i64().unwrap() > 100, "Zeilenmonster segmentiert");
    lf(&node, "d", "s", LinefsAktion::LinefsOeffnen { pfad: "monster.txt".into() }).await;
    let mut m2 = monster.clone();
    m2.replace_range(900_000..900_010, "XXXXXXXXXX");
    lf(&node, "d", "s", LinefsAktion::LinefsZeileSetzen { nr: 2, inhalt: m2 }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    let out = rendere(&node, "d", "monster.txt").await;
    assert!(out.contains("XXXXXXXXXX"));
    assert!(out.starts_with("vor\nmmm"));
}

#[tokio::test]
async fn hashkette_nach_50_fassungen() {
    let base = temp_base("linefs-ce-k");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    anlegen(&node, "d", "h.txt", "code", "start").await;
    for i in 1..=50 {
        lf(&node, "d", "s", LinefsAktion::LinefsOeffnen { pfad: "h.txt".into() }).await;
        lf(&node, "d", "s", LinefsAktion::LinefsZeileSetzen {
            nr: 1, inhalt: format!("stand-{i}"),
        }).await;
        lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    }
    let k = lf(&node, "d", "s", LinefsAktion::LinefsKettePruefen { pfad: "h.txt".into() }).await;
    assert_eq!(k["gruen"], true);
    assert_eq!(rendere(&node, "d", "h.txt").await, "stand-50");
    let alt = lf(&node, "d", "s", LinefsAktion::LinefsStandZuZeitpunkt {
        pfad: "h.txt".into(), fassung: 30,
    }).await;
    assert_eq!(alt["text"], "stand-29");
}

#[tokio::test]
async fn umbenennen_nur_mapping() {
    let base = temp_base("linefs-ce-u");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    anlegen(&node, "d", "alt.txt", "code", "inhalt").await;
    lf(&node, "d", "s", LinefsAktion::LinefsUmbenennen {
        pfad: "alt.txt".into(), neu: "neu.txt".into(),
    }).await;
    assert_eq!(rendere(&node, "d", "neu.txt").await, "inhalt");
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsRendere { pfad: "alt.txt".into() },
    }).await.unwrap_err();
    assert_eq!(e.code, "LINEFS");
}
