//! S1-Gegenproben: Format und Krypto müssen zu seed_welt2/kette passen.

use super::setup_crypto as sc;
use super::setup_hashdatei::HashdateiWriteNodeFactory;
use super::setup_auth::SetupAuthNodeFactory;
use crate::engine::NodeExecutorFactory;
use serde_json::json;
use uuid::Uuid;

fn nachricht(payload: serde_json::Value) -> crate::message::FlowMessage {
    crate::message::FlowMessage::new(Uuid::new_v4(), "hook", payload, Uuid::new_v4())
}

#[test]
fn hashdatei_format_ist_welt2() {
    let text = sc::hashdatei_bauen(
        &[("addr-a".into(), "Block-1".into())],
        &[("Block-1".into(), "CHIFFRE".into())],
    );
    assert!(text.starts_with("Argon2IDHashDatei/3\nwirt_min = 1.4.0\nnr = 1\n"));
    assert!(text.contains("Secretboxes\nAnfang\naddr-a = Block-1\nEnde"));
    let (addrs, blocks) = sc::hashdatei_parsen(&text);
    assert_eq!(addrs, vec![("addr-a".to_string(), "Block-1".to_string())]);
    assert_eq!(blocks, vec![("Block-1".to_string(), "CHIFFRE".to_string())]);
}

#[test]
fn echte_welt2_datei_wird_geparst() {
    let pfad = "/data/kronvault/kronvault-bucket-konzept/welt2/b2b-A/wkxd7llarlrqrswmdr7ym7st73kqinlg.txt";
    let Ok(text) = std::fs::read_to_string(pfad) else {
        eprintln!("Fixture fehlt, übersprungen");
        return;
    };
    let (addrs, blocks) = sc::hashdatei_parsen(&text);
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].0, "wkxd7llarlrqrswmdr7ym7st73kqinlg");
    assert_eq!(blocks.len(), 1);
    let box_val = sc::box_aus_b64(&blocks[0].1).unwrap();
    assert_eq!(box_val["aad"], "kv3-user");
}

#[tokio::test]
async fn hashdatei_write_baut_parsebares_format() {
    let node = HashdateiWriteNodeFactory
        .create(json!({"entriesPath": "secretboxes", "key": "b2b/x.txt"}))
        .await
        .unwrap();
    let out = node
        .process(nachricht(json!({
            "secretboxes": [
                {"addr": "a1", "block": "Block-1", "box_b64": "Qk9Y"},
                {"addr": "a2", "block": "Block-2", "box_b64": "Qk9YMg=="}
            ]
        })))
        .await
        .unwrap();
    let text = out[0].payload["hashdatei"].as_str().unwrap();
    let (addrs, blocks) = sc::hashdatei_parsen(text);
    assert_eq!(addrs.len(), 2);
    assert_eq!(blocks.len(), 2);
    assert_eq!(out[0].payload["files"][0]["key"], "b2b/x.txt");
}

#[tokio::test]
async fn setup_auth_ohne_pems_ist_403() {
    let node = SetupAuthNodeFactory
        .create(json!({"s3Config": "/etc/z8run/kv3-s3.json", "op": "plugin"}))
        .await
        .unwrap();
    let out = node.process(nachricht(json!({"s3": {"prefix": "x/"}}))).await.unwrap();
    assert_eq!(out[0].source_port, "error");
    assert_eq!(out[0].payload["status"], 403);
}
