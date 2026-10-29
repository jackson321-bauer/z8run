//! Baut EINEN Userspace der lokalen Welt (D6: kein Shared, getrennte DBs).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_db;
use super::setup_io::datei_eintrag;

pub struct UserBau {
    pub name: String,
    pub addr: String,
    pub master_sha256: String,
    pub pems: Vec<Value>,
    pub db: Value,
    pub block: Value,
    pub files: Vec<Value>,
}

fn write_pem(dir: &str, label: &str, pem: &str) -> Result<String, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("keys dir {dir}: {e}"))?;
    let path = format!("{dir}/{label}.pem");
    std::fs::write(&path, pem).map_err(|e| format!("write {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
pub async fn bau_user(
    prefix: &str,
    space: &str,
    u: &Value,
    key_dir: &str,
    db_dir: &str,
    vec0_path: &str,
    hw_keys: usize,
    setup_master_hex: &str,
) -> Result<UserBau, String> {
    let name = u["name"].as_str().ok_or("user.name fehlt")?.to_string();
    let password = u["password"].as_str().ok_or("user.password fehlt")?.to_string();
    let engines = u.get("engines").cloned().unwrap_or_else(|| json!([]));
    let space_salt = sc::salt_space(space);
    let salt_u = sc::salt_user(&space_salt, &name);
    let addr = sc::kette::adresse(&name, &salt_u)?;

    let master: Vec<u8> = (0u8..32).map(|_| rand::random::<u8>()).collect();
    let shares = sc::kette::shamir::split2(&master, &[1, 2])?;
    let db_key = sc::sha_hex(format!("kv3-db:{}", hex::encode(&master)).as_bytes());

    let user_db_dir = format!("{db_dir}/{addr}");
    let demo = setup_db::erzeugen(&user_db_dir, "demo", &db_key, vec0_path, space, &name).await?;
    let meta = setup_db::erzeugen(&user_db_dir, "meta", &db_key, vec0_path, space, &name).await?;
    let db = json!({
        "demo": {"key_hex": db_key, "sha256": demo.sha256, "bytes": demo.bytes, "vec0": demo.vec0},
        "meta": {"key_hex": db_key, "sha256": meta.sha256, "bytes": meta.bytes, "vec0": meta.vec0},
        "cipher": "sqlcipher",
        "wal": true,
        "fts5": true,
    });

    let block = json!({
        "shamir_provider": {"x": shares[0].x, "y_b64": B64.encode(&shares[0].y)},
        "engines": engines,
        "cluster": {"user-workspace": {"live": 10, "quorum": 3}},
        "workspace_bucket": format!("{prefix}workspaces/{addr}/"),
        "plugins": [],
        "key_type": "pem",
        "db": db.clone(),
    });
    let box_val = sc::passbox(&password, &salt_u, &block, "kv3-user")?;
    let user_text = sc::hashdatei_bauen(
        &[(addr.clone(), "Block-1".into())],
        &[("Block-1".into(), sc::box_b64(&box_val)?)],
    );
    let mut files = vec![datei_eintrag(
        format!("b2b/{addr}.txt"),
        user_text.into_bytes(),
        "utf8",
    )];

    let mut pems = Vec::new();
    let mut pub_pems = Vec::new();
    for i in 1..=hw_keys.max(1) {
        let paar = sc::gen_pem()?;
        let label = format!("{name}-hw{i}");
        let path = write_pem(key_dir, &label, &paar.pem)?;
        pub_pems.push(json!({"name": label, "pub_b64": paar.pub_b64, "path": path}));
        pems.push(json!({
            "name": label,
            "pem": paar.pem,
            "pub_b64": paar.pub_b64,
            "path": path,
        }));
    }
    let hw_block = json!({
        "shamir_hw": {"x": shares[1].x, "y_b64": B64.encode(&shares[1].y)},
        "hash_datei": format!("b2b/{addr}.txt"),
    });
    let mut addrs = Vec::new();
    let mut chiffren = Vec::new();
    for (i, p) in pub_pems.iter().enumerate() {
        let hb = sc::hwbox(p["pub_b64"].as_str().unwrap(), &hw_block, "kv3-hw")?;
        addrs.push((p["pub_b64"].as_str().unwrap().to_string(), format!("Block-{}", i + 1)));
        chiffren.push((format!("Block-{}", i + 1), sc::box_b64(&hb)?));
    }
    let hw_text = sc::hashdatei_bauen(&addrs, &chiffren);
    files.push(datei_eintrag(
        format!("workspaces/{addr}/hw-shards.txt"),
        hw_text.into_bytes(),
        "utf8",
    ));

    // Hausmeister-Escrow des HW-Shares (NUR mit Setup-Master öffenbar) für
    // spätere Box-Überarbeitung / Resharding (D1/D5).
    let escrow = json!({
        "shamir_hw": {"x": shares[1].x, "y_b64": B64.encode(&shares[1].y)},
        "user_addr": addr.clone(),
        "hash_datei": format!("b2b/{addr}.txt"),
    });
    let escrow_box = sc::passbox(setup_master_hex, "kv3-setup-escrow", &escrow, "kv3-setup-escrow")?;
    let escrow_text = sc::hashdatei_bauen(
        &[(addr.clone(), "Block-1".into())],
        &[("Block-1".into(), sc::box_b64(&escrow_box)?)],
    );
    files.push(datei_eintrag(
        format!("setup/escrow/{addr}.txt"),
        escrow_text.into_bytes(),
        "utf8",
    ));

    for (name_db, d) in [("demo", &demo), ("meta", &meta)] {
        let data = std::fs::read(&d.name).map_err(|e| format!("db read: {e}"))?;
        files.push(datei_eintrag(
            format!("workspaces/{addr}/db/{name_db}.db"),
            data,
            "base64",
        ));
    }

    Ok(UserBau {
        name,
        addr,
        master_sha256: sc::sha_hex(&master),
        pems,
        db,
        block,
        files,
    })
}
