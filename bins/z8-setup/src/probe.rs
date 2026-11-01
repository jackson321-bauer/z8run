//! `z8-setup put|replicas`: Quorum-Schreiben und Byte-Beweis je Provider.

use super::init::cfg_aus;

#[derive(clap::Args)]
pub struct Put {
    #[arg(long = "providers-config")]
    pub providers_config: String,
    #[arg(long)]
    pub bucket: Option<String>,
    #[arg(long)]
    pub prefix: Option<String>,
    #[arg(long = "quorum-min")]
    pub quorum_min: Option<usize>,
    #[arg(long)]
    pub key: String,
    #[arg(long)]
    pub file: std::path::PathBuf,
}

#[derive(clap::Args)]
pub struct Replicas {
    #[arg(long = "providers-config")]
    pub providers_config: String,
    #[arg(long)]
    pub bucket: Option<String>,
    #[arg(long)]
    pub prefix: Option<String>,
    #[arg(long)]
    pub key: String,
}

pub async fn put(a: Put) -> Result<(), String> {
    let cfg = cfg_aus(
        &a.providers_config,
        a.bucket.as_deref(),
        a.prefix.as_deref(),
        a.quorum_min,
    )?;
    let data = std::fs::read(&a.file).map_err(|e| format!("{}: {e}", a.file.display()))?;
    let info = cfg.put_quorum(&a.key, data).await?;
    println!(
        "PUT OK key={} ok={:?} failed={:?} degraded={}",
        info.key, info.replicas_ok, info.replicas_failed, info.degraded
    );
    Ok(())
}

pub async fn replicas(a: Replicas) -> Result<(), String> {
    let cfg = cfg_aus(
        &a.providers_config,
        a.bucket.as_deref(),
        a.prefix.as_deref(),
        None,
    )?;
    let hashes = cfg.replicas_eq(&a.key).await?;
    let mut werte: Vec<&String> = hashes.iter().map(|(_, h)| h).collect();
    werte.dedup();
    for (label, sha) in &hashes {
        println!("REPLICA {label} sha256={sha}");
    }
    println!(
        "REPLICAS key={} gleich={} provider={}",
        a.key,
        werte.len() == 1,
        hashes.len()
    );
    if werte.len() != 1 {
        return Err("Replikate sind NICHT byte-gleich".into());
    }
    Ok(())
}
