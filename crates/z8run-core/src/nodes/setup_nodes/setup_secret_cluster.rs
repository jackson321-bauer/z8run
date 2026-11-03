//! secret.db-Cluster je Userspace: eigener Bucket-Präfix, eigene S3-Keys im
//! "secrets"-Eintrag der User-Hashdatei (rw = Setup, ro = Proxy/User).

use serde_json::{json, Value};

use super::setup_crypto as sc;
use super::setup_io::S3Cfg;
use super::setup_secret_db;
use super::setup_secrets::{self as ss, SecretsProfil};

pub const SECRET_DB: &str = "secret.db";

fn cluster_id() -> String {
    hex::encode((0u8..8).map(|_| rand::random::<u8>()).collect::<Vec<_>>())
}

fn db_key() -> String {
    hex::encode((0u8..32).map(|_| rand::random::<u8>()).collect::<Vec<_>>())
}

fn providers(cfg: &S3Cfg) -> Vec<Value> {
    cfg.targets()
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
        .collect()
}

fn profil(
    cfg: &S3Cfg,
    cid: &str,
    key_hex: &str,
    read_only: bool,
) -> SecretsProfil {
    SecretsProfil {
        cluster_id: cid.to_string(),
        bucket: cfg.bucket.clone(),
        prefix: cfg.prefix.clone(),
        region: cfg.endpoint.region.clone(),
        providers: providers(cfg),
        db_key_hex: key_hex.to_string(),
        read_only,
    }
}

/// Baut eine S3Cfg ausschließlich aus dem "secrets"-Eintrag (kein zweiter
/// Wahrheitsort). Erster Provider ist der Primär-Pfad.
pub fn cfg_aus_profil(p: &SecretsProfil) -> Result<S3Cfg, String> {
    let Some(first) = p.providers.first() else {
        return Err("secrets-Eintrag ohne Provider".into());
    };
    let host = first["endpoint"]
        .as_str()
        .map(|e| e.trim_start_matches("https://").trim_start_matches("http://").to_string())
        .or_else(|| first["host"].as_str().map(str::to_string))
        .ok_or("secrets-Eintrag: Provider ohne endpoint")?;
    Ok(S3Cfg {
        endpoint: kv_store::s3::S3Endpoint {
            host,
            region: first["region"].as_str().unwrap_or(&p.region).to_string(),
            access_key: first["access_key"].as_str().unwrap_or_default().to_string(),
            secret_key: first["secret_key"].as_str().unwrap_or_default().to_string(),
        },
        bucket: first["bucket"].as_str().unwrap_or(&p.bucket).to_string(),
        prefix: p.prefix.clone(),
        multi: None,
    })
}

pub struct Auflage {
    pub cluster: Value,
    pub text: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn anlegen(
    base: &S3Cfg,
    req: &Value,
    user: &Value,
    password: &str,
    master_hex: &str,
    space: &str,
    out_dir: &str,
) -> Result<Auflage, String> {
    let name = user["name"].as_str().ok_or("user.name fehlt")?;
    let addr = user["addr_user"].as_str().ok_or("user.addr_user fehlt")?;
    let ov = req.get("secretS3").cloned().unwrap_or_else(|| json!({}));
    let mut secret = base.mit_override(&ov)?;
    let cid = cluster_id();
    if ov.get("prefix").and_then(|v| v.as_str()).is_none() {
        secret.prefix = format!("{}secret-cluster/{cid}/", base.prefix);
    } else if !secret.prefix.ends_with('/') {
        secret.prefix.push('/');
    }
    let key_hex = db_key();
    let dir = format!("{out_dir}/{cid}");
    std::fs::create_dir_all(&dir).map_err(|e| format!("secret dir {dir}: {e}"))?;
    let path = std::path::PathBuf::from(format!("{dir}/{SECRET_DB}"));
    let bytes = setup_secret_db::erzeuge(&path, &key_hex, space, name)?;
    let sha = sc::sha_hex(&bytes);
    secret.put(SECRET_DB, bytes.clone()).await?;

    let hash_key = format!("b2b/{addr}.txt");
    let raw = base.get(&hash_key).await?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let salt_u = sc::salt_user(&sc::salt_space(space), name);
    let ro = profil(&secret, &cid, &key_hex, true);
    let rw = profil(&secret, &cid, &key_hex, false);
    let ro_box = ss::profil_siegeln(&ro, password, &salt_u, "kv3-secrets-ro")?;
    let rw_box = ss::profil_siegeln(&rw, master_hex, ss::SECRETS_RW_SALT, "kv3-secrets-rw")?;
    let neu = ss::eintrag_hinzufuegen(&text, addr, &ro_box, &rw_box)?;
    let neu_sha = sc::sha_hex(neu.as_bytes());
    base.put(&hash_key, neu.clone().into_bytes()).await?;

    let cluster = json!({
        "ok": true,
        "user": name,
        "addr_user": addr,
        "cluster_id": cid,
        "bucket": secret.bucket,
        "prefix": secret.prefix,
        "secret_db_key": format!("{}{SECRET_DB}", secret.prefix),
        "secret_db_sha256": sha,
        "secret_db_bytes": bytes.len(),
        "hashdatei_key": hash_key,
        "hashdatei_sha256": neu_sha,
        "profiles": ["ro", "rw"],
    });
    Ok(Auflage { cluster, text: neu })
}

/// Lädt den rw-Eintrag eines Users (Setup-Seite) + die User-Hashdatei.
pub async fn lade_profil(
    base: &S3Cfg,
    addr: &str,
    master_hex: &str,
) -> Result<(SecretsProfil, String), String> {
    let key = format!("b2b/{addr}.txt");
    let raw = base.get(&key).await?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let p = ss::eintrag_oeffnen_rw(&text, addr, master_hex)?
        .ok_or_else(|| format!("secret: User {addr} hat keinen secrets-Eintrag"))?;
    Ok((p, text))
}

pub async fn lade_db(cfg: &S3Cfg) -> Result<Vec<u8>, String> {
    cfg.get(SECRET_DB).await
}

pub async fn speichere_db(cfg: &S3Cfg, data: &[u8]) -> Result<String, String> {
    cfg.put(SECRET_DB, data.to_vec()).await?;
    Ok(sc::sha_hex(data))
}
