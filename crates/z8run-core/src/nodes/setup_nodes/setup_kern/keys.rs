//! Setup-Kern: Keygen (Setup-PEMs 2-of-N, PQC, Registry-Start).

use serde_json::{json, Value};

use super::*;

fn schreibe(dir: &str, label: &str, inhalt: &str) -> Result<String, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("keys dir {dir}: {e}"))?;
    let path = format!("{dir}/{label}");
    std::fs::write(&path, inhalt).map_err(|e| format!("write {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn s3_beschreibung(cfg: &S3Cfg) -> Value {
    let providers: Vec<Value> = cfg
        .targets()
        .into_iter()
        .map(|(name, ep, bucket)| {
            json!({
                "name": name,
                "endpoint": format!("https://{}", ep.host),
                "region": ep.region,
                "bucket": bucket,
                "access_key": ep.access_key,
                "secret_key": ep.secret_key,
            })
        })
        .collect();
    json!({
        "host": cfg.endpoint.host,
        "region": cfg.endpoint.region,
        "bucket": cfg.bucket,
        "prefix": cfg.prefix,
        "access_key": cfg.endpoint.access_key,
        "secret_key": cfg.endpoint.secret_key,
        "providers": providers,
        "quorum_min": cfg.quorum_min(),
    })
}

pub async fn erzeugen(cfg: &S3Cfg, req: &Value) -> Result<KeygenOut, String> {
    let space = text(req, "space").ok_or("setup: space fehlt")?.to_string();
    let registry_key = text(req, "registryKey").unwrap_or(reg::REGISTRY_KEY);
    let shards_key = text(req, "shardsKey").unwrap_or(reg::SHARDS_KEY);
    if cfg.exists(registry_key).await {
        return Err("Welt bereits initialisiert — Betrieb nur mit Setup-Key (/setup nur einmal)".into());
    }
    let n = zahl(req, "setupKeys", 3).clamp(2, 16);
    let (key_dir, _, _) = pfade(req);
    let pqc_vorgaben: Vec<Option<String>> = req
        .get("pqc_pubkeys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|e| e.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let mut pems = Vec::new();
    let mut triples = Vec::new();
    for i in 0..n {
        let paar = sc::gen_pem()?;
        let label = format!("setup-hw{}", i + 1);
        let path = schreibe(&key_dir, &format!("{label}.pem"), &paar.pem)?;
        let (pqc_pub, pqc_dk_path) = pqc::pqc_paar_fuer(
            &label,
            &key_dir,
            pqc_vorgaben.get(i).and_then(|v| v.as_deref()),
        )?;
        let mldsa = pqc::gen_mldsa()?;
        let mldsa_path = schreibe(&key_dir, &format!("{label}-mldsa.pem"), &mldsa.sk_pem)?;
        pems.push(json!({
            "name": label,
            "pem": paar.pem,
            "pub_b64": paar.pub_b64,
            "pqc_pub_b64": pqc_pub,
            "mldsa_pub_b64": mldsa.pub_b64,
            "path": path,
            "pqc_dk_path": pqc_dk_path,
            "mldsa_sk_path": mldsa_path,
        }));
        triples.push((paar, pqc_pub, mldsa.pub_b64));
    }
    let master: Vec<u8> = (0u8..32).map(|_| rand::random::<u8>()).collect();
    let master_hex = hex::encode(&master);
    let (shards_text, setup_pubkeys) = reg::shards_bauen(&master, n, &triples)?;
    let mut registry = sc::leeres_registry(&space);
    registry["threshold"] = json!(2);
    registry["setup_keys"] = json!(setup_pubkeys);
    registry["s3"] = s3_beschreibung(cfg);
    registry["quorum"] = req
        .get("quorum")
        .cloned()
        .unwrap_or(json!({"n": n, "threshold": 2}));
    let files = vec![datei_eintrag(
        shards_key.to_string(),
        shards_text.into_bytes(),
        "utf8",
    )];
    Ok(KeygenOut {
        master_hex,
        pems,
        setup_pubkeys,
        files,
        registry,
    })
}

