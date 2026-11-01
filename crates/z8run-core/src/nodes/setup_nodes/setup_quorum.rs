//! Quorum-Operationen über ein Provider-Set (N Provider, Zwangsquorum min).
//!
//! Fail-closed: unter dem Zwangsquorum wird NICHTS geschrieben (Vorflug-HEAD).
//! Ueber dem Quorum mit Einzel-Ausfall: Write geht weiter + `degraded`.
//! Heilung: der naechste Write desselben Keys schreibt wieder an ALLE.

use kv_store::s3::S3Endpoint;
use sha2::Digest;

use super::setup_multi::WriteInfo;

pub type Target = (String, S3Endpoint, String);

pub async fn health(targets: &[Target]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (label, ep, bucket) in targets {
        out.push((label.clone(), ep.latency_ms(bucket).await.is_ok()));
    }
    out
}

pub async fn put(targets: &[Target], key: &str, data: Vec<u8>, min: usize) -> Result<WriteInfo, String> {
    let h = health(targets).await;
    let erreichbar = h.iter().filter(|(_, v)| *v).count();
    if erreichbar < min {
        return Err(format!(
            "Zwangsquorum verfehlt: {erreichbar}/{} erreichbar, min {min} — fail-closed",
            targets.len()
        ));
    }
    let mut handles = Vec::new();
    for (label, ep, bucket) in targets {
        let (ep, b, k, d) = (ep.clone(), bucket.clone(), key.to_string(), data.clone());
        handles.push((label.clone(), tokio::spawn(async move { ep.put_object(&b, &k, d).await })));
    }
    let (mut ok, mut failed) = (Vec::new(), Vec::new());
    for (label, h) in handles {
        match h.await {
            Ok(Ok(())) => ok.push(label),
            Ok(Err(e)) => {
                eprintln!("[quorum] write FEHLER {label}: {e}");
                failed.push(label)
            }
            Err(e) => {
                eprintln!("[quorum] write PANIC {label}: {e}");
                failed.push(label)
            }
        }
    }
    if ok.len() < min {
        return Err(format!(
            "Quorum verfehlt: {}/{} OK ({failed:?})",
            ok.len(),
            targets.len()
        ));
    }
    Ok(WriteInfo {
        key: key.to_string(),
        degraded: !failed.is_empty(),
        replicas_ok: ok,
        replicas_failed: failed,
    })
}

pub async fn get(targets: &[Target], key: &str) -> Result<Vec<u8>, String> {
    let mut handles = Vec::new();
    for (_, ep, bucket) in targets {
        let (ep, b, k) = (ep.clone(), bucket.clone(), key.to_string());
        handles.push(tokio::spawn(async move { ep.get_object(&b, &k).await }));
    }
    let mut err = None;
    for h in handles {
        match h.await {
            Ok(Ok(d)) => return Ok(d),
            Ok(Err(e)) => err = Some(e.to_string()),
            Err(e) => err = Some(e.to_string()),
        }
    }
    Err(format!("S3 GET {key}: {}", err.unwrap_or_else(|| "kein Provider".into())))
}

pub async fn list(targets: &[Target], key: &str) -> Result<Vec<(String, u64)>, String> {
    let mut err = None;
    for (_, ep, bucket) in targets {
        match ep.list_objects(bucket, key).await {
            Ok(objs) => return Ok(objs.into_iter().map(|o| (o.key, o.size)).collect()),
            Err(e) => err = Some(e.to_string()),
        }
    }
    Err(format!("S3 LIST {key}: {}", err.unwrap_or_default()))
}

pub async fn delete(targets: &[Target], key: &str) -> Result<(), String> {
    let mut err = None;
    for (_, ep, bucket) in targets {
        if let Err(e) = ep.delete_object(bucket, key).await {
            err = Some(e.to_string());
        }
    }
    match err {
        Some(e) => Err(format!("S3 DELETE {key}: {e}")),
        None => Ok(()),
    }
}

/// Bucket auf allen Providern anlegen (200/409 = OK).
pub async fn create_buckets(targets: &[Target]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (label, ep, bucket) in targets {
        match ep.call(reqwest::Method::PUT, bucket, &[], vec![]).await {
            Ok(_) => out.push((label.clone(), "created".into())),
            Err(e) => {
                let t = e.to_string();
                if t.contains("409") || t.contains("BucketAlready") {
                    out.push((label.clone(), "exists".into()));
                } else {
                    return Err(format!("create bucket {bucket} @ {label}: {t}"));
                }
            }
        }
    }
    Ok(out)
}

/// Liest denselben Key von ALLEN erreichbaren Providern und vergleicht die
/// Hashes — Beweis, dass die Replikate byte-gleich sind (S1/Quorum).
pub async fn replicas_eq(targets: &[Target], key: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (label, ep, bucket) in targets {
        let data = ep
            .get_object(bucket, key)
            .await
            .map_err(|e| format!("{label}: {e}"))?;
        out.push((label.clone(), hex::encode(sha2::Sha256::digest(&data))));
    }
    Ok(out)
}
