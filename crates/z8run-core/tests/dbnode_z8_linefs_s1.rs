//! S1 (a)-(e): Zeilen-Kern-Roundtrip, Historie/Grabmal, Kette, DECKEL,
//! Reservierungspflicht.

mod common;

use common::*;
use serde_json::{json, Value};
use z8run_core::dbnode::linefs_rows::{scheide, LinefsAktion, LinefsRequest};

async fn lf(node: &z8run_core::dbnode::DbNode, db: &str, s: &str, aktion: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: db.into(), session_id: s.into(), aktion })
        .await
        .unwrap()
}

async fn oeffne(node: &z8run_core::dbnode::DbNode, db: &str, s: &str, pfad: &str) -> Value {
    lf(node, db, s, LinefsAktion::LinefsOeffnen { pfad: pfad.into() }).await
}

#[tokio::test]
async fn a_roundtrip_mixed_endings_umlaute_segmente() {
    let base = temp_base("linefs-a");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let lang = "x".repeat(8192);
    let text = format!("eins\nzwei\r\ndrei\rü\n{lang}\nende");
    let v = lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "mix.txt".into(), art: "code".into(), text: text.clone(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    assert_eq!(v["fassung"], 1);
    let o = oeffne(&node, "d", "s", "mix.txt").await;
    assert_eq!(o["zeilen"].as_array().unwrap().len(), 6);
    // Schliessen ohne Aenderung = no-op, keine neue Fassung.
    let c = lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    assert_eq!(c["noop"], true);
    let r = lf(&node, "d", "s", LinefsAktion::LinefsRendere { pfad: "mix.txt".into() }).await;
    assert_eq!(r["text"].as_str().unwrap(), text, "byte-identischer Roundtrip");
    // Editieren: setzen + einfuegen + loeschen, Enden bleiben erhalten.
    oeffne(&node, "d", "s", "mix.txt").await;
    lf(&node, "d", "s", LinefsAktion::LinefsZeileSetzen { nr: 1, inhalt: "EINS".into() }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsEinfuegen { nr: 2, inhalt: "NEU".into() }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsZeileLoeschen { nr: 4 }).await;
    let c = lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    assert_eq!(c["fassung"], 2);
    let r = lf(&node, "d", "s", LinefsAktion::LinefsRendere { pfad: "mix.txt".into() }).await;
    let soll = format!("EINS\nNEU\nzwei\r\nü\n{lang}\nende");
    assert_eq!(r["text"].as_str().unwrap(), soll);
}

#[tokio::test]
async fn b_historie_alle_fassungen_und_grabmal() {
    let base = temp_base("linefs-b");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "h.txt".into(), art: "code".into(), text: "eins\nzwei\ndrei".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    let o = oeffne(&node, "d", "s", "h.txt").await;
    let key = o["zeilen"][1]["schluessel"].as_i64().unwrap();
    lf(&node, "d", "s", LinefsAktion::LinefsZeileSetzen { nr: 2, inhalt: "ZWEI".into() }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    oeffne(&node, "d", "s", "h.txt").await;
    lf(&node, "d", "s", LinefsAktion::LinefsZeileLoeschen { nr: 2 }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    let h = lf(&node, "d", "s", LinefsAktion::LinefsHistorie {
        pfad: "h.txt".into(), nr: 0, schluessel: Some(key),
    }).await;
    let hist = h["historie"].as_array().unwrap();
    assert_eq!(hist.len(), 3, "drei Fassungen: {hist:?}");
    assert_eq!(hist[0]["inhalt"], "zwei");
    assert_eq!(hist[1]["inhalt"], "ZWEI");
    assert_eq!(hist[2]["inhalt"], "", "Grabmal nach Loeschen");
}

#[tokio::test]
async fn c_kette_gruen_und_manipulation_rot() {
    let base = temp_base("linefs-c");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let v = lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "k.txt".into(), art: "code".into(), text: "a\nb\nc".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    let id = v["datei_id"].as_i64().unwrap();
    let g = lf(&node, "d", "s", LinefsAktion::LinefsKettePruefen { pfad: "k.txt".into() }).await;
    assert_eq!(g["gruen"], true);
    node.write("d", "s", "UPDATE zeilen_epochen SET inhalt='HACK' WHERE datei_id=?1 AND schluessel=1",
        vec![json!(id)]).await.unwrap();
    let rot = lf(&node, "d", "s", LinefsAktion::LinefsKettePruefen { pfad: "k.txt".into() }).await;
    assert_eq!(rot["gruen"], false, "Manipulation muss rot sein");
}

#[tokio::test]
async fn d_deckel_nullbyte_umbruch_und_invalid_utf8() {
    let base = temp_base("linefs-d");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsAnlegen {
            name: "bin.txt".into(), art: "code".into(), text: "a\0b".into(),
            urheber: "ki".into(), ordner_id: None,
        },
    }).await.unwrap_err();
    assert!(e.message.contains("Null-Byte"), "{e:?}");
    lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "ok.txt".into(), art: "code".into(), text: "a\nb".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    oeffne(&node, "d", "s", "ok.txt").await;
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsZeileSetzen { nr: 1, inhalt: "x\ny".into() },
    }).await.unwrap_err();
    assert!(e.message.contains("Zeilenumbruch"), "{e:?}");
    if let scheide::Urteil::Deckel(m) = scheide::pruefe(&[0x61, 0xe4, 0x62]) {
        assert!(m.contains("UTF-8") && m.contains("konvertieren"), "{m}");
    } else {
        panic!("Latin-1 muss DECKEL sein");
    }
}

#[tokio::test]
async fn e_schreiben_ohne_reservierung_ist_fehler() {
    let base = temp_base("linefs-e");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    let e = node.linefs(LinefsRequest {
        db_id: "d".into(), session_id: "niemand".into(),
        aktion: LinefsAktion::LinefsAnlegen {
            name: "x.txt".into(), art: "code".into(), text: "x".into(),
            urheber: "ki".into(), ordner_id: None,
        },
    }).await.unwrap_err();
    assert_eq!(e.code, "NOT_RESERVED", "{e:?}");
}
