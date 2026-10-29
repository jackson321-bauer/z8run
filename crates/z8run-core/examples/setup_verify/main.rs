//! Endpunkt-Verify für die Z8-Setup-Welt (S2/S3), angelehnt an seed_welt2 --verify.
//!
//! Aufruf:
//!   SETUP_RESP=resp.json SETUP_SPEC=spec.json SETUP_PREFIX=... \
//!   SETUP_PEMS="a.pem:b.pem" cargo run --release --example setup_verify
//! Prüft Login-Kette, DBs, Registry, Rotation und Extra-Pubkeys am Endpunkt.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;
use z8run_core::nodes::setup_nodes::setup_crypto as sc;
use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;
use z8run_core::nodes::setup_nodes::setup_registry as reg;

mod db;
use db::db_pruefen;

fn fail(msg: impl Into<String>) -> ! {
    eprintln!("VERIFY ROT: {}", msg.into());
    std::process::exit(1);
}

async fn hole(cfg: &S3Cfg, key: &str) -> Vec<u8> {
    match cfg.get(key).await {
        Ok(d) => d,
        Err(e) => fail(format!("S3 GET {key}: {e}")),
    }
}

#[tokio::main]
async fn main() {
    let resp: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("SETUP_RESP").expect("SETUP_RESP")).unwrap(),
    )
    .expect("resp json");
    let spec: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("SETUP_SPEC").expect("SETUP_SPEC")).unwrap(),
    )
    .expect("spec json");
    let prefix = std::env::var("SETUP_PREFIX").expect("SETUP_PREFIX");
    let mut cfg = S3Cfg::aus_datei(
        &std::env::var("SETUP_S3_CONFIG").unwrap_or_else(|_| "/etc/z8run/kv3-s3.json".into()),
    )
    .expect("s3 config");
    cfg.prefix = prefix.clone();
    let space = resp["space"].as_str().expect("space");
    println!("== VERIFY Z8-Setup space={space} prefix={prefix} ==");

    let salt_space = sc::salt_space(space);
    for user in resp["users"].as_array().expect("users") {
        let name = user["name"].as_str().unwrap();
        let addr = user["addr_user"].as_str().unwrap();
        let password = spec["users"]
            .as_array()
            .and_then(|a| a.iter().find(|u| u["name"] == name))
            .and_then(|u| u["password"].as_str())
            .unwrap_or_else(|| fail(format!("Passwort für {name} fehlt")));
        let salt_u = sc::salt_user(&salt_space, name);
        let text = String::from_utf8(hole(&cfg, &format!("b2b/{addr}.txt")).await).unwrap();
        let (addrs, blocks) = sc::hashdatei_parsen(&text);
        let block_name = addrs
            .iter()
            .find(|(a, _)| a == addr)
            .map(|(_, b)| b.clone())
            .unwrap_or_else(|| fail(format!("{name}: Adresse fehlt in Hashdatei")));
        let chiffre = blocks
            .iter()
            .find(|(b, _)| b == &block_name)
            .map(|(_, c)| c.clone())
            .unwrap();
        let box_val = sc::box_aus_b64(&chiffre).expect("box");
        let block = sc::passbox_oeffne(&box_val, password, &salt_u)
            .unwrap_or_else(|e| fail(format!("{name}: Passwort-Box: {e}")));
        let provider = &block["shamir_provider"];
        let p = sc::kette::shamir::Share {
            x: provider["x"].as_u64().unwrap() as u8,
            y: B64.decode(provider["y_b64"].as_str().unwrap()).unwrap(),
        };

        let hw_text =
            String::from_utf8(hole(&cfg, &format!("workspaces/{addr}/hw-shards.txt")).await).unwrap();
        let (ha, hb) = sc::hashdatei_parsen(&hw_text);
        let pem = match user["pems"][0]["pem"].as_str() {
            Some(p) => p.to_string(),
            None => std::fs::read_to_string(
                user["pems"][0]["path"].as_str().expect("user pem path"),
            )
            .expect("user pem lesen"),
        };
        let pub_b64 = sc::pem_pub_b64(&pem).unwrap();
        let hblk = ha
            .iter()
            .find(|(a, _)| a == &pub_b64)
            .map(|(_, b)| b.clone())
            .unwrap_or_else(|| fail(format!("{name}: PEM-Pubkey nicht in hw-shards")));
        let hchiffre = hb.iter().find(|(b, _)| b == &hblk).map(|(_, c)| c.clone()).unwrap();
        let hbox = sc::box_aus_b64(&hchiffre).unwrap();
        let hplain = sc::kette::hwbox_oeffne(&hbox, &pem)
            .unwrap_or_else(|e| fail(format!("{name}: HW-Box: {e}")));
        let hblock: Value = serde_json::from_slice(&hplain).unwrap();
        let h = &hblock["shamir_hw"];
        let hw = sc::kette::shamir::Share {
            x: h["x"].as_u64().unwrap() as u8,
            y: B64.decode(h["y_b64"].as_str().unwrap()).unwrap(),
        };
        let master = sc::kette::shamir::combine2(&p, &hw)
            .unwrap_or_else(|e| fail(format!("{name}: Shamir: {e}")));
        let got = sc::sha_hex(&master);
        let soll = user["user_master_sha256"].as_str().unwrap();
        if got != soll {
            fail(format!("{name}: Master {got} != {soll}"));
        }
        println!("  [1] LOGIN OK {name} addr={addr} master={}", &got[..16]);
        if block["workspace_bucket"].as_str().unwrap_or_default().is_empty() {
            fail(format!("{name}: workspace_bucket fehlt"));
        }

        for db in ["demo", "meta"] {
            let key_hex = block["db"][db]["key_hex"].as_str().unwrap();
            let soll_db = block["db"][db]["sha256"].as_str().unwrap();
            let bytes = hole(&cfg, &format!("workspaces/{addr}/db/{db}.db")).await;
            if sc::sha_hex(&bytes) != soll_db {
                fail(format!("{name}: {db}.db sha256 weicht ab"));
            }
            db_pruefen(key_hex, &bytes, &format!("{name}-{db}")).await;
        }
        println!("  [2] DBs OK {name} (SQLCipher+WAL+FTS5+vec0-Flag={})", block["db"]["demo"]["vec0"]);
    }

    if let Ok(pems_env) = std::env::var("SETUP_PEMS") {
        let pems: Vec<String> = pems_env
            .split(':')
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        let master = reg::master_aus_pems(&cfg, reg::SHARDS_KEY, &pems)
            .await
            .unwrap_or_else(|e| fail(format!("Setup-Master: {e}")));
        let registry = reg::lade_registry(&cfg, reg::REGISTRY_KEY, &hex::encode(&master))
            .await
            .unwrap_or_else(|e| fail(format!("Registry: {e}")));
        if registry["users"].as_array().map(|a| a.len()).unwrap_or(0) != resp["users"].as_array().unwrap().len() {
            fail("Registry-Userzahl weicht ab");
        }
        if registry["shared"].as_bool().unwrap_or(true) {
            fail("Registry meldet shared=true (D6 verletzt)");
        }
        let raw = String::from_utf8(hole(&cfg, reg::REGISTRY_KEY).await).unwrap();
        if raw.contains(&cfg.endpoint.access_key) || raw.contains(&cfg.endpoint.secret_key) {
            fail("Registry enthält S3-Keys im Klartext");
        }
        if raw.contains("shamir_provider") || raw.contains(&format!("\"{space}\"")) {
            fail("Registry ist nicht vollständig verschlüsselt");
        }
        let wcount: usize = registry["webauthn"]
            .as_object()
            .map(|o| o.values().filter_map(|v| v.as_array()).map(|a| a.len()).sum())
            .unwrap_or(0);
        if std::env::var("SETUP_EXPECT_WEBAUTHN").is_ok() && wcount == 0 {
            fail("WebAuthn-Credentials fehlen in der Registry");
        }
        println!("  [3] REGISTRY OK (Setup-Quorum 2-of-N, users={}, shared=false, s3_keys_encrypted=true, webauthn_cred={wcount})", registry["users"].as_array().unwrap().len());
    }

    if let Ok(extra) = std::env::var("SETUP_EXTRA_PEM") {
        let pem = std::fs::read_to_string(&extra).unwrap();
        let pub_b64 = sc::pem_pub_b64(&pem).unwrap();
        let mut gefunden = false;
        for user in resp["users"].as_array().unwrap() {
            let addr = user["addr_user"].as_str().unwrap();
            let text = String::from_utf8(hole(&cfg, &format!("workspaces/{addr}/hw-shards.txt")).await).unwrap();
            let (ha, hb) = sc::hashdatei_parsen(&text);
            if let Some((_, blk)) = ha.iter().find(|(a, _)| a == &pub_b64) {
                let chiffre = hb.iter().find(|(b, _)| b == blk).map(|(_, c)| c.clone()).unwrap();
                let hbox = sc::box_aus_b64(&chiffre).unwrap();
                let hplain = sc::kette::hwbox_oeffne(&hbox, &pem)
                    .unwrap_or_else(|e| fail(format!("Extra-PEM öffnet Box nicht: {e}")));
                let hblock: Value = serde_json::from_slice(&hplain).unwrap();
                if hblock["shamir_hw"]["x"].as_u64().is_none() {
                    fail("Extra-Pubkey-Box ohne shamir_hw");
                }
                println!("  [4] EXTRA PUBKEY OK {} block={blk}", user["name"].as_str().unwrap());
                gefunden = true;
            }
        }
        if !gefunden {
            fail("Extra-Pubkey nicht in hw-shards");
        }
    }

    if let Ok(old) = std::env::var("SETUP_OLD_PREFIX") {
        let mut old_cfg = S3Cfg::aus_datei(
            &std::env::var("SETUP_S3_CONFIG").unwrap_or_else(|_| "/etc/z8run/kv3-s3.json".into()),
        )
        .unwrap();
        old_cfg.prefix = old.clone();
        let rest = old_cfg.list("").await.unwrap_or_else(|e| fail(format!("S3 LIST {old}: {e}")));
        if !rest.is_empty() {
            fail(format!("alter Prefix {old} nicht leer: {} Objekte", rest.len()));
        }
        println!("  [5] ROTATION OK alter Prefix {old} ist leer (Objekte ersetzt)");
    }

    println!("== VERIFY GRUEN ==");
}
