//! S5-Matrix: Binär-Zeilen (hochladen/zeigen/holen, Übergänge) über
//! linefs_blobs — kein binaer_s3/Secret.db.

mod common;

use base64::Engine;
use common::*;
use serde_json::Value;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, a: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: "d".into(), session_id: "s".into(), aktion: a })
        .await
        .unwrap()
}

#[tokio::test]
async fn binaer_matrix_und_uebergaenge() {
    let base = temp_base("linefs-s5-bin");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    lf(&node, LinefsAktion::LinefsAnlegen {
        name: "text.txt".into(), art: "code".into(), text: "a\nb".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;

    // hochladen (base64) + zeigen + holen (base64 und Datei)
    let roh = base64::engine::general_purpose::STANDARD.encode(b"hallo binaer");
    let m = lf(&node, LinefsAktion::LinefsBinaerHochladen {
        name: "roh.bin".into(), mime: "application/octet-stream".into(),
        datei_pfad: None, bytes_b64: Some(roh.clone()), owner: "ki".into(),
    }).await;
    let blob_id = m["blob_id"].as_str().unwrap().to_string();
    let z = lf(&node, LinefsAktion::LinefsBinaerZeigen { blob_id: Some(blob_id.clone()) }).await;
    assert_eq!(z["sha256"], m["sha256"]);
    let h = lf(&node, LinefsAktion::LinefsBinaerHolen {
        blob_id: blob_id.clone(), ziel_pfad: None,
    }).await;
    assert_eq!(h["bytes_b64"], roh);
    let ziel = base.join("ziel.bin");
    lf(&node, LinefsAktion::LinefsBinaerHolen {
        blob_id, ziel_pfad: Some(ziel.to_string_lossy().to_string()),
    }).await;
    assert_eq!(std::fs::read(&ziel).unwrap(), b"hallo binaer");

    // Text -> Binaer (Grabmale + Status) -> Text (Zeilen aus Blob neu)
    let tr = lf(&node, LinefsAktion::LinefsUebergangZuBinaer {
        pfad: "text.txt".into(), name: "text.bin".into(),
        mime: "application/octet-stream".into(),
    }).await;
    assert_eq!(tr["status"], "binaer");
    let zurueck = lf(&node, LinefsAktion::LinefsUebergangZuText { pfad: "text.txt".into() }).await;
    assert_eq!(zurueck["status"], "text");
    let r = lf(&node, LinefsAktion::LinefsRendere { pfad: "text.txt".into() }).await;
    assert_eq!(r["text"], "a\nb");
    let k = lf(&node, LinefsAktion::LinefsKettePruefen { pfad: "text.txt".into() }).await;
    assert_eq!(k["gruen"], true);
}
