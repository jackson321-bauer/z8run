//! S2 (a)-(f): Ordner-Baum, Pfad-Aufloesung, Verschieben mit Kindern,
//! Zyklus-Verbot, Integritaet (verwaiste Datei), WAL-Abdeckung.

mod common;

use base64::Engine;
use common::*;
use serde_json::{json, Value};
use std::path::Path;
use z8run_core::dbnode::crypto::KeyEnvelope;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::wal::{WalInner, WalObject};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, db: &str, s: &str, a: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: db.into(), session_id: s.into(), aktion: a })
        .await
        .unwrap()
}

async fn ordner(node: &DbNode, db: &str, eltern: i64, name: &str) -> i64 {
    let v = lf(node, db, "s", LinefsAktion::OrdnerAnlegen {
        eltern_id: eltern, name: name.into(),
    }).await;
    v["id"].as_i64().unwrap()
}

#[tokio::test]
async fn a_bis_f_ordner_komplett() {
    let base = temp_base("linefs-s2");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();

    // (a) 3-Ebenen-Baum
    let a = ordner(&node, "d", 0, "a").await;
    let b = ordner(&node, "d", a, "b").await;
    let c = ordner(&node, "d", b, "c").await;
    let liste = lf(&node, "d", "s", LinefsAktion::OrdnerListen { eltern_id: 0 }).await;
    let eintraege = liste["eintraege"].as_array().unwrap();
    assert_eq!(eintraege[0]["name"], "a");
    assert_eq!(eintraege[0]["kinder"][0]["name"], "b");
    assert_eq!(eintraege[0]["kinder"][0]["kinder"][0]["name"], "c");

    // (b) Datei in Ordner + Pfad-Aufloesung
    let f = lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "datei.txt".into(), art: "code".into(), text: "inhalt\n".into(),
        urheber: "ki".into(), ordner_id: Some(c),
    }).await;
    let id = f["datei_id"].as_i64().unwrap();
    let p = lf(&node, "d", "s", LinefsAktion::OrdnerPfadAufloesen {
        pfad: "a/b/c/datei.txt".into(),
    }).await;
    assert_eq!(p["datei_id"], id);
    assert_eq!(p["pfad"], "a/b/c/datei.txt");

    // (d) Zyklus: a unter c haengen = Fehler
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::OrdnerVerschieben { id: a, neuer_eltern_id: c },
    }).await.unwrap_err();
    assert!(e.message.contains("ZYKLUS"), "{e:?}");

    // (c) Verschieben mit Kindern: b nach Wurzel -> Pfade in der Sicht neu
    lf(&node, "d", "s", LinefsAktion::OrdnerVerschieben {
        id: b, neuer_eltern_id: 0,
    }).await;
    let p2 = lf(&node, "d", "s", LinefsAktion::OrdnerPfadAufloesen {
        pfad: "b/c/datei.txt".into(),
    }).await;
    assert_eq!(p2["datei_id"], id);
    assert_eq!(p2["pfad"], "b/c/datei.txt");
    let alt = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::OrdnerPfadAufloesen { pfad: "a/b/c/datei.txt".into() },
    }).await;
    assert!(alt.is_err(), "alter Pfad darf nicht mehr treffen");

    // (e) verwaiste Datei: Ordner extern wegloeschen -> Integritaetsfehler
    let x = ordner(&node, "d", 0, "x").await;
    lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "lost.txt".into(), art: "code".into(), text: "x".into(),
        urheber: "ki".into(), ordner_id: Some(x),
    }).await;
    node.write("d", "s", "DELETE FROM ordner WHERE id=?1", vec![json!(x)]).await.unwrap();
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsAnlegen {
            name: "trigger.txt".into(), art: "code".into(), text: "x".into(),
            urheber: "ki".into(), ordner_id: None,
        },
    }).await.unwrap_err();
    assert!(e.message.contains("ORDNER-INTEGRITAET"), "{e:?}");

    // (f) WAL deckt Ordner-Ops ab (entschluesselt, art:linefs mit ordner-SQL)
    let key = KeyEnvelope::derive(&master(), "d").unwrap();
    let dir = base.join("c").join("d").join("wal");
    let mut ordner_ops = 0;
    let mut linefs_wal = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") { continue; }
        let nr: u64 = p.file_stem().unwrap().to_string_lossy().parse().unwrap();
        let obj: WalObject = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let sealed = base64::engine::general_purpose::STANDARD.decode(&obj.seal).unwrap();
        let plain = z8run_core::dbnode::crypto::open(&key, "d", nr, &obj.prev_hash, &sealed).unwrap();
        let inner: WalInner = serde_json::from_slice(&plain).unwrap();
        if inner.art == "linefs" {
            linefs_wal += 1;
            ordner_ops += inner.ops.iter().filter(|a| a.sql.contains("ordner")).count();
        }
    }
    assert!(linefs_wal >= 3);
    assert!(ordner_ops >= 4, "Ordner-Ops im WAL: {ordner_ops}");
    assert!(Path::new(&dir).exists());
}
