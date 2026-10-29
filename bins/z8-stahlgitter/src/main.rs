//! z8-stahlgitter — Big-Bang-Migration + Gegenprobe (Z8-STAHLGITTER).
//!
//! `migrate`: öffnet alle Alt-Boxen (v1/v2) mit den Halter-PEMs und siegelt
//! sie hybrid v3 (ECC P-256 + ML-KEM-1024) neu — gleiche Identität/AAD/Inhalt.
//! `verify`: prüft, dass KEINE asymmetrische Alt-Box mehr existiert.

mod keys;
mod migrate;
mod world2;

use serde_json::{json, Value};
use std::path::PathBuf;

use z8run_core::nodes::setup_nodes::setup_crypto as sc;
use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;

fn box_aus_b64(t: &str) -> Result<Value, String> {
    sc::box_aus_b64(t)
}
fn box_b64(v: &Value) -> Result<String, String> {
    sc::box_b64(v)
}

struct Args {
    cmd: String,
    s3_config: Option<String>,
    prefix: Option<String>,
    keys: Vec<PathBuf>,
    local: Vec<PathBuf>,
    report: Option<PathBuf>,
    dir: Option<PathBuf>,
    key: Option<PathBuf>,
    msg: Option<String>,
    label: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        cmd: String::new(),
        s3_config: None,
        prefix: None,
        keys: Vec::new(),
        local: Vec::new(),
        report: None,
        dir: None,
        key: None,
        msg: None,
        label: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "migrate" | "verify" | "world2" | "mldsa-sign" | "mldsa-pub" | "pqc-gen" => a.cmd = x,
            "--s3-config" => a.s3_config = it.next(),
            "--prefix" => a.prefix = it.next(),
            "--keys" => a.keys.push(PathBuf::from(it.next().ok_or("--keys ohne Wert")?)),
            "--local" => a.local.push(PathBuf::from(it.next().ok_or("--local ohne Wert")?)),
            "--report" => a.report = it.next().map(PathBuf::from),
            "--dir" => a.dir = it.next().map(PathBuf::from),
            "--key" => a.key = it.next().map(PathBuf::from),
            "--msg" => a.msg = it.next(),
            "--label" => a.label = it.next(),
            "-h" | "--help" => {
                return Err("usage: z8-stahlgitter <migrate|verify> [--s3-config F] [--prefix P] [--keys DIR]... [--local DIR]... [--report F]".into())
            }
            other => return Err(format!("unbekanntes Argument: {other}")),
        }
    }
    if a.cmd.is_empty() {
        return Err("Modus fehlt (migrate|verify)".into());
    }
    Ok(a)
}

fn s3cfg(a: &Args) -> Result<Option<S3Cfg>, String> {
    let Some(path) = &a.s3_config else { return Ok(None) };
    let base = S3Cfg::aus_datei(path)?;
    let ov = match &a.prefix {
        Some(p) => json!({"prefix": p}),
        None => json!({}),
    };
    Ok(Some(base.mit_override(&ov)?))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("FEHLER: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let a = parse_args()?;
    if a.cmd == "pqc-gen" {
        use z8run_core::nodes::setup_nodes::setup_pqc as pqc;
        let dir = a.dir.ok_or("--dir fehlt")?;
        let label = a.label.ok_or("--label fehlt")?;
        let dir_s = dir.to_string_lossy().to_string();
        let (pub_b64, dk_path) = pqc::pqc_paar_fuer(&label, &dir_s, None)?;
        println!("{}", serde_json::json!({
            "pqc_pub_b64": pub_b64, "pqc_dk_path": dk_path
        }));
        return Ok(());
    }
    if a.cmd == "mldsa-sign" || a.cmd == "mldsa-pub" {
        use z8run_core::nodes::setup_nodes::setup_pqc as pqc;
        let key = a.key.ok_or("--key <mldsa-pem> fehlt")?;
        let pem = std::fs::read_to_string(&key).map_err(|e| e.to_string())?;
        if a.cmd == "mldsa-pub" {
            println!("{}", pqc::mldsa_pub(&pem)?);
        } else {
            let msg = a.msg.ok_or("--msg fehlt")?;
            println!("{}", pqc::mldsa_sign(&pem, msg.as_bytes())?);
        }
        return Ok(());
    }
    if a.cmd == "world2" {
        let dir = a.dir.ok_or("world2 braucht --dir <welt2-verzeichnis>")?;
        let out = world2::pruefe(&dir)?;
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        if let Some(p) = &a.report {
            std::fs::write(p, serde_json::to_vec_pretty(&out).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    let mut km = keys::laden(&a.keys)?;
    let mut b = migrate::Bericht::default();
    if a.cmd == "migrate" {
        if let Some(cfg) = s3cfg(&a)? {
            migrate::s3(&cfg, &mut km, &mut b).await;
        }
        for dir in &a.local {
            migrate::lokal(dir, &mut km, &mut b);
        }
        keys::fixture_aktualisieren(&a.keys)?;
    } else {
        if let Some(cfg) = s3cfg(&a)? {
            match cfg.list("").await {
                Ok(list) => {
                    for (full, _) in list {
                        if !full.ends_with(".txt") {
                            continue;
                        }
                        let rel = full.strip_prefix(&cfg.prefix).unwrap_or(&full).to_string();
                        match cfg.get(&rel).await {
                            Ok(d) => migrate::pruefe_text(
                                &String::from_utf8_lossy(&d),
                                &rel,
                                &mut b,
                            ),
                            Err(e) => b.fehler.push(format!("{rel}: GET {e}")),
                        }
                    }
                }
                Err(e) => b.fehler.push(format!("S3 LIST: {e}")),
            }
        }
        for dir in &a.local {
            let mut dateien = Vec::new();
            sammle(dir, &mut dateien);
            for p in dateien {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    migrate::pruefe_text(&t, &p.display().to_string(), &mut b);
                }
            }
        }
    }
    let out = json!({
        "ok": b.fehler.is_empty(),
        "modus": a.cmd,
        "migrierte_dateien": b.v3_neu,
        "unveraendert": b.unveraendert,
        "v3_boxen": b.v3_neu,
        "fehler": b.fehler,
        "dateien": b.dateien,
        "erzeugte_pqc_keys": km.erzeugt,
        "uebersprungen": b.uebersprungen,
    });
    let text = serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?;
    if let Some(p) = &a.report {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(p, &text).map_err(|e| format!("report {}: {e}", p.display()))?;
    }
    println!("{text}");
    if !b.fehler.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

fn sammle(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            sammle(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("txt") {
            out.push(p);
        }
    }
}
