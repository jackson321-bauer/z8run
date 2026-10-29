//! S1-Gegenproben: Format und Krypto müssen zu seed_welt2/kette passen.

use super::setup_crypto as sc;
use super::setup_seal_boxes::*;
use super::setup_seal_keys::*;
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
async fn pem_seal_und_kette_oeffnen_rundlauf() {
    let gen = PemGenNodeFactory.create(json!({"count": 2, "prefix": "t"})).await.unwrap();
    let out = gen.process(nachricht(json!({}))).await.unwrap();
    let pems = out[0].payload["pems"].as_array().unwrap().clone();
    assert_eq!(pems.len(), 2);

    let seal = HwboxSealNodeFactory.create(json!({"pemsPath": "pems", "blockPath": "block"})).await.unwrap();
    let out = seal
        .process(nachricht(json!({
            "pems": pems,
            "block": {"shamir_hw": {"x": 2, "y": "QUJD"}},
        })))
        .await
        .unwrap();
    let boxes = out[0].payload["secretboxes"].as_array().unwrap().clone();
    assert_eq!(boxes.len(), 2);
    for (i, b) in boxes.iter().enumerate() {
        let box_val = sc::box_aus_b64(b["box_b64"].as_str().unwrap()).unwrap();
        let plain = sc::kette::hwbox_oeffne(
            &box_val,
            pems[i]["pem"].as_str().unwrap(),
        )
        .unwrap();
        let block: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(block["shamir_hw"]["x"], 2);
    }
}

#[tokio::test]
async fn passbox_rundlauf_und_fremdes_passwort_scheitert() {
    let node = PassboxSealNodeFactory.create(json!({
        "passwordPath": "password", "saltPath": "salt",
        "addrPath": "addr", "blockPath": "block", "blockName": "Block-1"
    })).await.unwrap();
    let s = sc::salt_user(&sc::salt_space("gamma"), "anna");
    let out = node
        .process(nachricht(json!({
            "password": "geheim-123",
            "salt": s,
            "addr": "abc",
            "block": {"engines": ["demo"]},
        })))
        .await
        .unwrap();
    let box_val = &out[0].payload["box"];
    let plain = sc::kette::passbox_oeffne(box_val, "geheim-123", &s).unwrap();
    let block: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(block["engines"][0], "demo");
    assert!(sc::kette::passbox_oeffne(box_val, "falsch", &s).is_err());
    assert!(out[0].payload.get("password").is_none());
}

#[tokio::test]
async fn shamir_mehrere_shares_und_adresse_wie_kette() {
    let node = ShamirSplit2NodeFactory.create(json!({"shares": 3, "emitMaster": true})).await.unwrap();
    let out = node.process(nachricht(json!({}))).await.unwrap();
    let shares = out[0].payload["shares"].as_array().unwrap().clone();
    assert_eq!(shares.len(), 3);
    let master_hex = out[0].payload["master_hex"].as_str().unwrap();
    assert_eq!(sc::sha_hex(&hex::decode(master_hex).unwrap()), out[0].payload["master_sha256"].as_str().unwrap());
    let s = |i: usize| sc::kette::shamir::Share {
        x: shares[i]["x"].as_u64().unwrap() as u8,
        y: base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            shares[i]["y_b64"].as_str().unwrap(),
        )
        .unwrap(),
    };
    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        let master = sc::kette::shamir::combine2(&s(i), &s(j)).unwrap();
        assert_eq!(hex::encode(master), master_hex);
    }
    let addr = sc::kette::adresse("anna", &sc::salt_user(&sc::salt_space("gamma"), "anna")).unwrap();
    assert_eq!(addr.len(), 32);
    assert!(addr.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}

#[tokio::test]
async fn setup_world_baut_zwei_userspaces_ohne_shared() {
    use super::setup_io as io;
    use super::setup_registry as reg;
    use super::setup_world_factory::SetupWorldNodeFactory;

    let base = std::env::temp_dir().join(format!("z8setup-world-{}", Uuid::new_v4()));
    let master_hex = hex::encode([7u8; 32]);
    let mut registry = sc::leeres_registry("gamma");
    registry["setup_keys"] = json!([{"name": "setup-hw1", "pub_b64": "x", "x": 1}]);
    let node = SetupWorldNodeFactory
        .create(json!({
            "vec0Path": "/tmp/vecprobe/vec0.so",
            "registryKey": reg::REGISTRY_KEY,
        }))
        .await
        .unwrap();
    let req = json!({
        "s3": {"prefix": "z8setup/unit/"},
        "setup_master_hex": master_hex,
        "setup_registry": registry,
        "space": "gamma",
        "keyOutDir": base.to_string_lossy(),
        "users": [
            {"name": "anna", "password": "anna-pass-123", "engines": ["demo"]},
            {"name": "bernd", "password": "bernd-pass-123", "engines": ["demo", "fts5"]}
        ],
        "files": [],
    });
    let out = node.process(nachricht(req)).await.unwrap();
    assert_eq!(out[0].source_port, "output");
    let payload = &out[0].payload;
    let world = &payload["world"];
    assert_eq!(world["users"].as_array().unwrap().len(), 2);
    assert_eq!(world["shared"], false);
    assert!(payload.get("setup_master_hex").is_some());

    let files = payload["files"].as_array().unwrap();
    let find = |key: &str| files.iter().find(|f| f["key"] == key).cloned();
    let salt_space = sc::salt_space("gamma");
    for user in world["users"].as_array().unwrap() {
        let name = user["name"].as_str().unwrap();
        let addr = user["addr_user"].as_str().unwrap();
        let salt_u = sc::salt_user(&salt_space, name);
        let text = String::from_utf8(io::datei_bytes(&find(&format!("b2b/{addr}.txt")).unwrap()).unwrap()).unwrap();
        let (addrs, blocks) = sc::hashdatei_parsen(&text);
        assert_eq!(addrs[0].0, addr);
        let box_val = sc::box_aus_b64(&blocks[0].1).unwrap();
        let block = sc::kette::passbox_oeffne(&box_val, &format!("{name}-pass-123"), &salt_u).unwrap();
        let block: serde_json::Value = serde_json::from_slice(&block).unwrap();
        let provider = &block["shamir_provider"];
        let p = sc::kette::shamir::Share {
            x: provider["x"].as_u64().unwrap() as u8,
            y: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, provider["y_b64"].as_str().unwrap()).unwrap(),
        };
        let pems = user["pems"].as_array().unwrap();
        assert_eq!(pems.len(), 2);
        let hw_text = String::from_utf8(io::datei_bytes(&find(&format!("workspaces/{addr}/hw-shards.txt")).unwrap()).unwrap()).unwrap();
        let (ha, hb) = sc::hashdatei_parsen(&hw_text);
        let pub_b64 = sc::pem_pub_b64(pems[0]["pem"].as_str().unwrap()).unwrap();
        let blk = ha.iter().find(|(a, _)| a == &pub_b64).unwrap().1.clone();
        let hbox = sc::box_aus_b64(&hb.iter().find(|(b, _)| b == &blk).unwrap().1).unwrap();
        let hplain = sc::kette::hwbox_oeffne(&hbox, pems[0]["pem"].as_str().unwrap()).unwrap();
        let hblock: serde_json::Value = serde_json::from_slice(&hplain).unwrap();
        let h = &hblock["shamir_hw"];
        let hw = sc::kette::shamir::Share {
            x: h["x"].as_u64().unwrap() as u8,
            y: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, h["y_b64"].as_str().unwrap()).unwrap(),
        };
        let master = sc::kette::shamir::combine2(&p, &hw).unwrap();
        assert_eq!(sc::sha_hex(&master), user["user_master_sha256"].as_str().unwrap());
        assert!(block["db"]["demo"]["key_hex"].as_str().unwrap().len() == 64);
        assert_eq!(block["db"]["demo"]["vec0"], true);
        let db = io::datei_bytes(&find(&format!("workspaces/{addr}/db/demo.db")).unwrap()).unwrap();
        assert!(db.len() > 4096);
        // DB ist verschlüsselt: Klartext-Marker darf nicht im Kopf stehen.
        assert!(!db.windows(6).any(|w| w == b"SQLite"));
    }
    let reg_text = String::from_utf8(io::datei_bytes(&find(reg::REGISTRY_KEY).unwrap()).unwrap()).unwrap();
    let regbox = sc::box_aus_b64(&reg_text).unwrap();
    let plain = sc::registry_oeffne(&master_hex, &regbox).unwrap();
    assert_eq!(plain["users"].as_array().unwrap().len(), 2);
    assert_eq!(plain["shared"], false);
    let _ = std::fs::remove_dir_all(&base);
}

