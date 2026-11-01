//! `z8-setup health`: Provider-Erreichbarkeit + Bucket-Anlage.

use super::init::cfg_aus;

#[derive(clap::Args)]
pub struct Health {
    #[arg(long = "providers-config")]
    pub providers_config: String,
    #[arg(long)]
    pub bucket: Option<String>,
    #[arg(long)]
    pub prefix: Option<String>,
    #[arg(long = "create-buckets", default_value_t = false)]
    pub create_buckets: bool,
}

pub async fn run(a: Health) -> Result<(), String> {
    let cfg = cfg_aus(
        &a.providers_config,
        a.bucket.as_deref(),
        a.prefix.as_deref(),
        None,
    )?;
    if a.create_buckets {
        let b = cfg.create_buckets().await?;
        println!("BUCKETS {b:?}");
    }
    let h = cfg.health().await;
    for (label, ok) in &h {
        println!("PROVIDER {label} reachable={ok}");
    }
    if h.iter().all(|(_, ok)| !ok) {
        return Err("kein Provider erreichbar".into());
    }
    Ok(())
}
