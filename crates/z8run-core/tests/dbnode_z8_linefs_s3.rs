//! S3 (a)(b): Zeilen-Limit als Konfig (0 = unbegrenzt), Code/Doku-Scheide.

mod common;

use common::*;
use serde_json::Value;
use std::time::Instant;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::types::{DbError, DbNodeConfig};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, db: &str, s: &str, a: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: db.into(), session_id: s.into(), aktion: a })
        .await
        .unwrap()
}

fn mit_limit(limit: u32, code_docu: bool) -> DbNode {
    DbNode::new(DbNodeConfig {
        zeilen_limit: limit,
        code_docu_unterscheidung: code_docu,
        ..Default::default()
    })
}

async fn anlegen(node: &DbNode, db: &str, name: &str, art: &str, text: &str) -> Result<Value, DbError> {
    node.linefs(LinefsRequest {
        db_id: db.into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsAnlegen {
            name: name.into(), art: art.into(), text: text.into(),
            urheber: "ki".into(), ordner_id: None,
        },
    }).await
}

#[tokio::test]
async fn a_limit_5_blockt_und_limit_0_erlaubt_10000() {
    let base = temp_base("linefs-s3-a");
    let node = mit_limit(5, false);
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let fuenf = (1..=5).map(|i| i.to_string()).collect::<Vec<_>>().join("\n");
    anlegen(&node, "d", "f.txt", "code", &fuenf).await.unwrap();
    lf(&node, "d", "s", LinefsAktion::LinefsOeffnen { pfad: "f.txt".into() }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsEinfuegen { nr: 6, inhalt: "sechs".into() }).await;
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsSchliessen,
    }).await.unwrap_err();
    assert!(e.message.contains("ZEILEN-LIMIT"), "{e:?}");
    // Eine Zeile loeschen -> wieder 5, Commit geht.
    lf(&node, "d", "s", LinefsAktion::LinefsZeileLoeschen { nr: 1 }).await;
    let c = lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    assert_eq!(c["fassung"], 2);

    // limit = 0 (Default): 10.000 Zeilen, Performance-Messwert im Log.
    let base2 = temp_base("linefs-s3-a2");
    let offen = DbNode::new(DbNodeConfig::default());
    offen.open_db("d", &master(), cluster("c", &base2)).await.unwrap();
    offen.reserve("d", "s").unwrap();
    let gross = (1..=10_000).map(|i| i.to_string()).collect::<Vec<_>>().join("\n");
    let t0 = Instant::now();
    anlegen(&offen, "d", "gross.txt", "dokument", &gross).await.unwrap();
    let t_anlegen = t0.elapsed().as_millis();
    let t1 = Instant::now();
    let r = lf(&offen, "d", "s", LinefsAktion::LinefsRendere { pfad: "gross.txt".into() }).await;
    let t_render = t1.elapsed().as_millis();
    assert_eq!(r["text"].as_str().unwrap(), gross);
    println!("LIMIT0_10000_ZEILEN anlegen_ms={t_anlegen} render_ms={t_render}");
}

#[tokio::test]
async fn b_code_doku_aus_und_an() {
    let base = temp_base("linefs-s3-b");
    let aus = mit_limit(5, false);
    aus.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    aus.reserve("d", "s").unwrap();
    let sechs = (1..=6).map(|i| i.to_string()).collect::<Vec<_>>().join("\n");
    let e = anlegen(&aus, "d", "d.md", "dokument", &sechs).await.unwrap_err();
    assert!(e.message.contains("ZEILEN-LIMIT"), "aus = keine Sonderbehandlung: {e:?}");

    let base2 = temp_base("linefs-s3-b2");
    let an = mit_limit(5, true);
    an.open_db("d", &master(), cluster("c", &base2)).await.unwrap();
    an.reserve("d", "s").unwrap();
    anlegen(&an, "d", "d.md", "dokument", &sechs).await.unwrap();
    let e = anlegen(&an, "d", "c.txt", "code", &sechs).await.unwrap_err();
    assert!(e.message.contains("ZEILEN-LIMIT"), "Code bleibt begrenzt: {e:?}");
}
