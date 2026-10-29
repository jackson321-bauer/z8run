//! Gegenprobe: setup-world baut N Userspaces ohne Shared (D6).

use serde_json::json;
use uuid::Uuid;

use super::setup_crypto as sc;
use super::setup_io as io;
use super::setup_registry as reg;
use super::setup_world_factory::SetupWorldNodeFactory;
use crate::engine::NodeExecutorFactory;

fn nachricht(payload: serde_json::Value) -> crate::message::FlowMessage {
    crate::message::FlowMessage::new(Uuid::new_v4(), "hook", payload, Uuid::new_v4())
}

#[tokio::test]
async fn setup_world_baut_zwei_userspaces_ohne_shared() {
    let base = std::env::temp_dir().join(format!("z8setup-world-{}", Uuid::new_v4()));
    let master_hex = hex::encode([7u8; 32]);
    let pw_anna = format!("dummy-anna-{}", Uuid::new_v4());
    let pw_bernd = format!("dummy-bernd-{}", Uuid::new_v4());
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
            {"name": "anna", "password": pw_anna, "engines": ["demo"]},
            {"name": "bernd", "password": pw_bernd, "engines": ["demo", "fts5"]}
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
        let pw = if name == "anna" { &pw_anna } else { &pw_bernd };
        let block = sc::kette::passbox_oeffne(&box_val, pw, &salt_u).unwrap();
        let block: serde_json::Value = serde_json::from_slice(&block).unwrap();
        let provider = &block["shamir_provider"];
        let p = sc::kette::shamir::Share {
            x: provider["x"].as_u64().unwrap() as u8,
            y: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, provider["y_b64"].as_str().unwrap()).unwrap(),
        };
        let pems = user["pems"].as_array().unwrap();
        assert_eq!(pems.len(), 2);
        assert!(pems[0].get("pem").is_none(), "API darf keine privaten User-PEMs liefern");
        let hw_text = String::from_utf8(io::datei_bytes(&find(&format!("workspaces/{addr}/hw-shards.txt")).unwrap()).unwrap()).unwrap();
        let (ha, hb) = sc::hashdatei_parsen(&hw_text);
        let pem0 = std::fs::read_to_string(pems[0]["path"].as_str().unwrap()).unwrap();
        let pub_b64 = sc::pem_pub_b64(&pem0).unwrap();
        let blk = ha.iter().find(|(a, _)| a == &pub_b64).unwrap().1.clone();
        let hbox = sc::box_aus_b64(&hb.iter().find(|(b, _)| b == &blk).unwrap().1).unwrap();
        let pqc_path = pems[0]["pqc_dk_path"].as_str().unwrap();
        let kem_dk = super::setup_pqc::lese_kem_dk(pqc_path).unwrap();
        let hblock = super::setup_pqc::hwbox_oeffne_v3(&hbox, &pem0, &kem_dk).unwrap();
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

