//! JSONL-Export der otel-DB + MANIFEST (sha256 je Datei, gesiegelt, F9).
//! Blob-Referenzen (span_id <-> blob_id) wandern in das Manifest, nie die
//! Blobs selbst (Blob-Manager regelt die Speicherung laengst).

use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use proxy_kern::{ProxyError, Span};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::meta::MetaStore;
use crate::otel::OtelStore;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct ExportOptions {
    pub dir: PathBuf,
    pub seal_key: Vec<u8>,
    pub trace_id: Option<String>,
}

pub async fn export(
    otel: &OtelStore,
    meta: &MetaStore,
    opts: &ExportOptions,
) -> Result<Value, ProxyError> {
    let spans = match &opts.trace_id {
        Some(t) => otel.query_trace(t).await?,
        None => otel.all().await?,
    };
    let metas = meta
        .query(opts.trace_id.as_deref(), None, 1_000_000)
        .await?;
    std::fs::create_dir_all(&opts.dir)
        .map_err(|e| ProxyError::Internal(format!("Export-Verzeichnis: {e}")))?;
    let spans_path = opts.dir.join("spans.jsonl");
    let meta_path = opts.dir.join("meta.jsonl");
    write_jsonl(&spans_path, &spans)?;
    let meta_lines: Vec<Value> = metas
        .iter()
        .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
        .collect();
    write_jsonl(&meta_path, &meta_lines)?;

    let blob_refs = blob_refs(&spans);
    let files = vec![
        file_entry("spans.jsonl", &spans_path, spans.len())?,
        file_entry("meta.jsonl", &meta_path, metas.len())?,
    ];
    let mut manifest = json!({
        "version": 1,
        "created_ms": now_ms(),
        "trace_id": opts.trace_id,
        "files": files,
        "blob_refs": blob_refs,
    });
    let sealed = seal(&opts.seal_key, &manifest)?;
    manifest["sealed"] = Value::from(sealed);
    let manifest_path = opts.dir.join("MANIFEST.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| ProxyError::Internal(format!("Manifest: {e}")))?,
    )
    .map_err(|e| ProxyError::Internal(format!("Manifest schreiben: {e}")))?;
    Ok(manifest)
}

fn write_jsonl(path: &Path, rows: &[impl serde::Serialize]) -> Result<(), ProxyError> {
    let mut text = String::new();
    for row in rows {
        let line = serde_json::to_string(row)
            .map_err(|e| ProxyError::Internal(format!("JSONL: {e}")))?;
        text.push_str(&line);
        text.push('\n');
    }
    std::fs::write(path, text)
        .map_err(|e| ProxyError::Internal(format!("{}: {e}", path.display())))
}

fn file_entry(name: &str, path: &Path, rows: usize) -> Result<Value, ProxyError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ProxyError::Internal(format!("{}: {e}", path.display())))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(json!({
        "name": name,
        "sha256": hex::encode(h.finalize()),
        "bytes": bytes.len(),
        "rows": rows,
    }))
}

fn blob_refs(spans: &[Span]) -> Vec<Value> {
    let mut out = Vec::new();
    for s in spans {
        if let Some(id) = s.attrs.get("blob_id").and_then(|v| v.as_str()) {
            out.push(json!({"span_id": s.span_id, "blob_id": id}));
        }
        if let Some(id) = s.attrs.get("blob_ref").and_then(|v| v.as_str()) {
            out.push(json!({"span_id": s.span_id, "blob_id": id}));
        }
    }
    out
}

fn seal(key: &[u8], manifest: &Value) -> Result<String, ProxyError> {
    if key.is_empty() {
        return Err(ProxyError::Internal("Export-Siegelkey fehlt".into()));
    }
    let bytes = serde_json::to_vec(manifest)
        .map_err(|e| ProxyError::Internal(format!("Manifest kanonisch: {e}")))?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| ProxyError::Internal("HMAC-Key".into()))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Prueft das Siegel (Test/Abnahme): HMAC ueber Manifest ohne `sealed`.
pub fn verify(key: &[u8], manifest: &Value) -> bool {
    let Some(sealed) = manifest.get("sealed").and_then(|v| v.as_str()) else {
        return false;
    };
    let mut copy = manifest.clone();
    if let Value::Object(map) = &mut copy {
        map.remove("sealed");
    }
    seal(key, &copy).map(|s| s == sealed).unwrap_or(false)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
