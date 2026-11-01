//! `z8-setup init`: komplette Welt ueber das Provider-Set (+ Quorum).

use serde_json::{json, Value};

use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;
use z8run_core::nodes::setup_nodes::setup_kern;

#[derive(clap::Args)]
pub struct Init {
    #[arg(long)]
    pub space: String,
    /// Wiederholbar: "name:passwort"
    #[arg(long = "user", required = true)]
    pub user: Vec<String>,
    #[arg(long = "providers-config")]
    pub providers_config: String,
    #[arg(long)]
    pub bucket: Option<String>,
    #[arg(long)]
    pub prefix: Option<String>,
    #[arg(long = "key-dir")]
    pub key_dir: Option<String>,
    #[arg(long = "db-dir")]
    pub db_dir: Option<String>,
    #[arg(long)]
    pub vec0: Option<String>,
    #[arg(long = "hw-keys", default_value_t = 2)]
    pub hw_keys: usize,
    #[arg(long = "setup-keys", default_value_t = 3)]
    pub setup_keys: usize,
    #[arg(long = "quorum-min")]
    pub quorum_min: Option<usize>,
    /// Optionaler ML-KEM-Pubkey (Base64) fuer den ersten Setup-Key
    #[arg(long = "hw-pub")]
    pub hw_pub: Vec<String>,
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
    #[arg(long = "create-buckets", default_value_t = false)]
    pub create_buckets: bool,
}

pub fn cfg_aus(path: &str, bucket: Option<&str>, prefix: Option<&str>, min: Option<usize>) -> Result<S3Cfg, String> {
    setup_kern::cfg_aus(path, bucket, prefix, min)
}

pub async fn run(a: Init) -> Result<(), String> {
    let cfg = cfg_aus(
        &a.providers_config,
        a.bucket.as_deref(),
        a.prefix.as_deref(),
        a.quorum_min,
    )?;
    if a.create_buckets {
        let b = cfg.create_buckets().await?;
        eprintln!("[bucket] {b:?}");
    }
    let mut users = Vec::new();
    for u in &a.user {
        let (name, pw) = u
            .split_once(':')
            .ok_or_else(|| format!("--user braucht name:passwort (war {u:?})"))?;
        users.push(json!({"name": name, "password": pw}));
    }
    let mut req = json!({
        "space": a.space,
        "users": users,
        "setupKeys": a.setup_keys,
        "hwKeys": a.hw_keys,
        "quorum": {"n": cfg.targets().len(), "threshold": cfg.quorum_min()},
    });
    if let Some(v) = a.key_dir { req["keyOutDir"] = json!(v); }
    if let Some(v) = a.db_dir { req["dbOutDir"] = json!(v); }
    if let Some(v) = a.vec0 { req["vec0Path"] = json!(v); }
    if !a.hw_pub.is_empty() { req["pqc_pubkeys"] = json!(a.hw_pub); }
    let resp = setup_kern::init_welt(&cfg, &req).await?;
    if resp["provider_degraded"].as_bool() == Some(true) {
        eprintln!("[warnung] provider_degraded=true (ein Provider fehlt, Quorum hielt)");
    }
    if let Some(out) = a.out {
        let text = serde_json::to_string_pretty(&resp).map_err(|e| e.to_string())?;
        std::fs::write(&out, text).map_err(|e| format!("out {}: {e}", out.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
        }
    }
    let users: Vec<Value> = resp["users"].as_array().map(|a| a.iter().map(|u| json!({"name": u["name"], "addr": u["addr_user"]})).collect()).unwrap_or_default();
    let pems: Vec<Value> = resp["setup_pems"].as_array().map(|a| a.iter().map(|p| p["path"].clone()).collect()).unwrap_or_default();
    println!(
        "Z8-SETUP OK space={} addr_space={} users={} files={} pems={:?} degraded={}",
        resp["space"].as_str().unwrap_or_default(),
        resp["addr_space"].as_str().unwrap_or_default(),
        serde_json::to_string(&users).unwrap_or_default(),
        resp["files"].as_array().map(|a| a.len()).unwrap_or(0),
        pems,
        resp["provider_degraded"].as_bool().unwrap_or(false),
    );
    Ok(())
}
