//! Registry-, Extra-Key- und Rotationsprüfungen für setup_verify.

use serde_json::Value;

use super::{fail, hole};
use z8run_core::nodes::setup_nodes::setup_crypto as sc;
use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;
use z8run_core::nodes::setup_nodes::setup_pqc as pqc;
use z8run_core::nodes::setup_nodes::setup_registry as reg;

pub async fn registry(cfg: &S3Cfg, resp: &Value, space: &str) {
    if let Ok(pems_env) = std::env::var("SETUP_PEMS") {
        let pem_paths: Vec<&str> = pems_env.split(':').collect();
        let pems: Vec<String> = pem_paths
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        let kem_dks: Vec<Vec<u8>> = pem_paths
            .iter()
            .map(|p| pqc::lese_kem_dk(&p.replace(".pem", ".kem")).unwrap())
            .collect();
        let master = reg::master_aus_pems(&cfg, reg::SHARDS_KEY, &pems, &kem_dks)
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
                let dk_path = std::env::var("SETUP_EXTRA_PQC_DK")
                    .unwrap_or_else(|_| extra.replace(".pem", ".kem"));
                let dk = pqc::lese_kem_dk(&dk_path)
                    .unwrap_or_else(|e| fail(format!("Extra-PQC-DK: {e}")));
                let hblock = pqc::hwbox_oeffne_v3(&hbox, &pem, &dk)
                    .unwrap_or_else(|e| fail(format!("Extra-PEM öffnet Box nicht: {e}")));
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
}
