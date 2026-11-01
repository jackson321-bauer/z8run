//! Setup-Kern: Welt-Bau (N Userspaces, Registry-Fortschreibung, D6).

use serde_json::{json, Value};

use super::*;

fn oeffentlich(db: &Value) -> Value {
    let mut d = db.clone();
    for name in ["demo", "meta"] {
        if let Some(o) = d.get_mut(name).and_then(|v| v.as_object_mut()) {
            o.remove("key_hex");
        }
    }
    d
}

pub async fn bauen(cfg: &S3Cfg, req: &Value, k: &KeygenOut) -> Result<WeltOut, String> {
    let space = text(req, "space").ok_or("setup: space fehlt")?.to_string();
    let mut registry = k.registry.clone();
    if registry["space"].as_str() != Some(space.as_str()) {
        return Err("Registry gehört zu anderem Space".into());
    }
    let users = req
        .get("users")
        .and_then(|v| v.as_array())
        .ok_or("setup: users[] fehlt")?;
    if users.is_empty() {
        return Err("setup: users[] ist leer".into());
    }
    let (base, db_dir, vec0) = pfade(req);
    let key_dir = format!("{base}/users");
    let hw = zahl(req, "hwKeys", 2).clamp(1, 8);
    let mut files: Vec<Value> = k
        .files
        .iter()
        .filter(|f| f["key"].as_str() != Some(reg::REGISTRY_KEY))
        .cloned()
        .collect();
    let mut users_out = Vec::new();
    let mut reg_users = Vec::new();
    for u in users {
        let b = bau_user(&cfg.prefix, &space, u, &key_dir, &db_dir, &vec0, hw, &k.master_hex).await?;
        files.extend(b.files.iter().cloned());
        let pubkeys: Vec<Value> = b
            .pems
            .iter()
            .map(|p| {
                json!({
                    "name": p["name"],
                    "pub_b64": p["pub_b64"],
                    "pqc_pub_b64": p["pqc_pub_b64"],
                    "path": p["path"],
                })
            })
            .collect();
        users_out.push(json!({
            "name": b.name,
            "addr_user": b.addr,
            "user_master_sha256": b.master_sha256,
            "workspace_bucket": b.block["workspace_bucket"],
            "engines": b.block["engines"],
            "db": oeffentlich(&b.db),
            "pubkeys": pubkeys,
            "pems": b.pems.iter().map(|p| json!({
                "name": p["name"], "pub_b64": p["pub_b64"],
                "pqc_pub_b64": p["pqc_pub_b64"],
                "path": p["path"], "pqc_dk_path": p["pqc_dk_path"]
            })).collect::<Vec<_>>(),
        }));
        reg_users.push(json!({
            "name": b.name,
            "addr_user": b.addr,
            "user_master_sha256": b.master_sha256,
            "workspace_bucket": b.block["workspace_bucket"],
            "engines": b.block["engines"],
            "pubkeys": pubkeys,
            "db": oeffentlich(&b.db),
        }));
    }
    let addr_space = sc::kette::adresse(&space, &sc::salt_space(&space))?;
    registry["space_addr"] = json!(addr_space);
    registry["users"] = json!(reg_users);
    registry["multi_user"] = json!(users.len() > 1);
    registry["shared"] = json!(false);
    registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
    Ok(WeltOut {
        users: users_out,
        files,
        registry,
        addr_space,
    })
}
