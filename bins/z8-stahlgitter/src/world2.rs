//! Login-Gegenprobe gegen die neu gesiegelte Welt2-Sim: volle Kette
//! Passwort-Box (Argon2id) + HW-Box (v3 hybrid) → Master → SHA-256.
//! Sollwert kommt aus dem unveränderten fixture/zugangsdaten.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::path::Path;
use z8run_core::nodes::setup_nodes::setup_crypto::{hashdatei_parsen, kette, sha_hex};

fn box_aus(t: &str) -> Result<Value, String> {
    crate::box_aus_b64(t)
}

fn kem_dk(pem_path: &Path) -> Result<Vec<u8>, String> {
    let side = pem_path.with_extension("kem.json");
    let meta: Value = serde_json::from_slice(
        &std::fs::read(&side).map_err(|e| format!("kem.json {}: {e}", side.display()))?,
    )
    .map_err(|e| e.to_string())?;
    let path = meta["dk_path"].as_str().ok_or("dk_path fehlt")?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("kem dk {path}: {e}"))?;
    B64.decode(text.trim()).map_err(|e| e.to_string())
}

pub fn pruefe(world: &Path) -> Result<Value, String> {
    let fix: Value = serde_json::from_slice(
        &std::fs::read(world.join("zugangsdaten/fixture.json"))
            .map_err(|e| format!("fixture: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let space_a = fix["space_a"].as_str().ok_or("space_a fehlt")?;
    let salt_a = sha_hex(format!("kv3-salt:{space_a}").as_bytes());
    let mut out = Vec::new();
    for u in fix["users"].as_array().ok_or("users fehlt")? {
        let name = u["name"].as_str().ok_or("name fehlt")?;
        let pw = u["password"].as_str().ok_or("password fehlt")?;
        let soll = u["master_sha256"].as_str().ok_or("master_sha256 fehlt")?;
        let salt_u = sha_hex(format!("{salt_a}:user:{name}").as_bytes());
        let addr = kette::adresse(name, &salt_u)?;

        // 1) Provider-Shard aus der Passwort-Box
        let text = std::fs::read_to_string(world.join(format!("b2b-A/{addr}.txt")))
            .map_err(|e| format!("b2b {addr}: {e}"))?;
        let (addrs, blocks) = hashdatei_parsen(&text);
        let bn = addrs.iter().find(|(a, _)| a == &addr).map(|(_, b)| b.clone()).ok_or("addr fehlt")?;
        let chiffre = blocks.iter().find(|(b, _)| b == &bn).map(|(_, c)| c.clone()).ok_or("box fehlt")?;
        let pbox = box_aus(&chiffre)?;
        let pblock: Value = serde_json::from_slice(&kette::passbox_oeffne(&pbox, pw, &salt_u)?)
            .map_err(|e| e.to_string())?;
        let p = &pblock["shamir_provider"];
        let ytxt = p["y_b64"].as_str().or_else(|| p["y"].as_str()).ok_or("y fehlt")?;
        let provider = kette::shamir::Share {
            x: p["x"].as_u64().ok_or("x fehlt")? as u8,
            y: B64.decode(ytxt).map_err(|e| e.to_string())?,
        };

        // 2) HW-Shard aus der hybriden v3-Box (PEM + ML-KEM-1024-dk)
        let pem_path = world.join(format!("keys/{name}-hw1.pem"));
        let pem = std::fs::read_to_string(&pem_path).map_err(|e| format!("pem: {e}"))?;
        let pub_b64 = z8run_core::nodes::setup_nodes::setup_crypto::pem_pub_b64(&pem)?;
        let hw_text = std::fs::read_to_string(world.join(format!("workspaces/{addr}/hw-shards.txt")))
            .map_err(|e| format!("hw-shards: {e}"))?;
        let (ha, hb) = hashdatei_parsen(&hw_text);
        let hbn = ha.iter().find(|(a, _)| a == &pub_b64).map(|(_, b)| b.clone()).ok_or("hw pub fehlt")?;
        let hch = hb.iter().find(|(b, _)| b == &hbn).map(|(_, c)| c.clone()).ok_or("hw box fehlt")?;
        let hbox = box_aus(&hch)?;
        if hbox["v"].as_u64() != Some(3) {
            return Err(format!("{name}: HW-Box ist nicht v3"));
        }
        let dk = kem_dk(&pem_path)?;
        let plain_hw = kette::hwbox_oeffne_pqc(&hbox, &pem, &dk)?;
        let hblock: Value = serde_json::from_slice(&plain_hw).map_err(|e| e.to_string())?;
        let h = &hblock["shamir_hw"];
        let hytxt = h["y_b64"].as_str().or_else(|| h["y"].as_str()).ok_or("y fehlt")?;
        let hw = kette::shamir::Share {
            x: h["x"].as_u64().ok_or("x fehlt")? as u8,
            y: B64.decode(hytxt).map_err(|e| e.to_string())?,
        };

        // 3) Master + Sollwert-Vergleich (UNVERÄNDERT)
        let master = kette::shamir::combine2(&provider, &hw)?;
        let ist = hex::encode(&master);
        if ist != soll {
            return Err(format!("{name}: Master-Fingerprint geändert ({ist} != {soll})"));
        }
        out.push(json!({"user": name, "addr": addr, "master_sha256": ist, "box": "v3"}));
    }
    Ok(json!({"ok": true, "welt": world.display().to_string(), "users": out}))
}
