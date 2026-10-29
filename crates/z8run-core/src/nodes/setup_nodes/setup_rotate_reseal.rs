//! Re-Seal der Boxen bei /rotate-s3 (D4): gleiche Shards+Salts, neue Nonces.
//!
//! Passwort-Boxen werden mit dem User-Passwort neu versiegelt, Setup-Blöcke
//! mit dem Setup-Master, HW-Boxen mit dem Escrow-Share an jeden User-Pubkey.
//! Ohne Passwörter gibt es kein Re-Seal — dann bleibt es eine S3-Relocation.

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::S3Cfg;

fn passwort<'a>(pw: &'a Value, name: &str, addr: &str) -> Option<&'a str> {
    pw.get(name)
        .or_else(|| pw.get(addr))
        .and_then(|v| v.as_str())
}

pub async fn reseal(
    cfg: &S3Cfg,
    registry: &Value,
    master_hex: &str,
    passwords: &Value,
) -> Result<Vec<Value>, String> {
    let space = registry["space"].as_str().ok_or("registry.space fehlt")?;
    let salt_space = sc::salt_space(space);
    let users = registry["users"]
        .as_array()
        .ok_or("registry.users fehlt")?
        .clone();
    let mut out = Vec::new();
    for u in &users {
        let name = u["name"].as_str().ok_or("user.name fehlt")?;
        let addr = u["addr_user"].as_str().ok_or("user.addr fehlt")?;
        let pw = passwort(passwords, name, addr)
            .ok_or_else(|| format!("rotateBoxes: Passwort für {name} fehlt"))?;
        let salt_u = sc::salt_user(&salt_space, name);

        // 1) b2b-Hashdatei: User-Box + Setup-Plugin-Box neu versiegeln
        let key = format!("b2b/{addr}.txt");
        let before = cfg.get(&key).await?;
        let (addrs, blocks) = sc::hashdatei_parsen(&String::from_utf8_lossy(&before));
        let map: std::collections::HashMap<String, String> =
            blocks.into_iter().collect();
        let mut new_chiffren = Vec::new();
        for (a, b) in &addrs {
            let Some(chiffre) = map.get(b) else { continue };
            let box_val = sc::box_aus_b64(chiffre)?;
            let neu = if a == addr {
                let block = sc::passbox_oeffne(&box_val, pw, &salt_u)?;
                sc::passbox(pw, &salt_u, &block, "kv3-user")?
            } else if a == &format!("setup-plugins-{addr}") {
                let block = sc::passbox_oeffne(&box_val, master_hex, "kv3-setup-plugins")?;
                sc::passbox(master_hex, "kv3-setup-plugins", &block, "kv3-setup-plugins")?
            } else {
                box_val
            };
            new_chiffren.push((b.clone(), sc::box_b64(&neu)?));
        }
        let neu_text = sc::hashdatei_bauen(&addrs, &new_chiffren);
        cfg.put(&key, neu_text.clone().into_bytes()).await?;
        out.push(json!({"key": key, "before": sc::sha_hex(&before), "after": sc::sha_hex(neu_text.as_bytes())}));

        // 2) hw-shards: HW-Share aus Escrow an jeden Pubkey neu versiegeln
        let hw_key = format!("workspaces/{addr}/hw-shards.txt");
        let hw_before = cfg.get(&hw_key).await?;
        let escrow_text = String::from_utf8_lossy(&cfg.get(&format!("setup/escrow/{addr}.txt")).await?).to_string();
        let (ea, eb) = sc::hashdatei_parsen(&escrow_text);
        let eblk = ea.iter().find(|(a, _)| a == addr).map(|(_, b)| b.clone()).ok_or("Escrow-Block fehlt")?;
        let echiffre = eb.iter().find(|(b, _)| b == &eblk).map(|(_, c)| c.clone()).ok_or("Escrow-Chiffre fehlt")?;
        let ebox = sc::box_aus_b64(&echiffre)?;
        let escrow = sc::passbox_oeffne(&ebox, master_hex, "kv3-setup-escrow")?;
        let hw_block = json!({
            "shamir_hw": escrow["shamir_hw"],
            "hash_datei": format!("b2b/{addr}.txt"),
        });
        let (ha, _hb) = sc::hashdatei_parsen(&String::from_utf8_lossy(&hw_before));
        let mut hw_chiffren = Vec::new();
        for (pub_b64, block) in &ha {
            let neu = sc::hwbox(pub_b64, &hw_block, "kv3-hw")?;
            hw_chiffren.push((block.clone(), sc::box_b64(&neu)?));
        }
        let hw_text = sc::hashdatei_bauen(&ha, &hw_chiffren);
        cfg.put(&hw_key, hw_text.clone().into_bytes()).await?;
        out.push(json!({"key": hw_key, "before": sc::sha_hex(&hw_before), "after": sc::sha_hex(hw_text.as_bytes())}));
    }
    Ok(out)
}
