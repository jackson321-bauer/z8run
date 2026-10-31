//! GESAMT-EXPORT-CONTAINER (G12–G15): ein PQC-Container mit Verzeichnis
//! {manifest.json + JSONL/Blobs}. Jeder Export bekommt einen FRISCHEN
//! Content-Key (nie der DB-Master); Empfänger-Box ueber die bestehende
//! Pyramide (PQC-Pubkey oder Passwort). Klartext verlaesst den Container nie.

use super::blob_export_key::{open_container_key, seal_container_key, BoxMode, OpenBox};
use super::blob_io::{decrypt_part, encrypt_part};
use super::types::{DbError, DbResult};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const CONTAINER_FORMAT: &str = "z8-export-container/1";
const CONTAINER_CHUNK: usize = 256 * 1024;

fn err_from(e: String) -> DbError {
    match e.split_once(": ") {
        Some((code, msg)) => DbError::new(code, msg),
        None => DbError::new("EXPORT_CONTAINER", e),
    }
}

fn aad(name: &str) -> String {
    format!("z8-export:{name}")
}

/// Versiegelt ein Verzeichnis (Name -> Bytes) plus Manifest in einen Container.
pub fn seal(
    files: &[(String, Vec<u8>)],
    mut manifest: Value,
    mode: BoxMode<'_>,
) -> DbResult<(Vec<u8>, Value)> {
    let ck: [u8; 32] = rand::random();
    // Secret-Huellen: Klartext NUR hier im Speicher, im Manifest steht
    // ausschliesslich der mit dem Container-Key versiegelte Umschlag.
    if let Some(values) = manifest.get_mut("secret_values").and_then(Value::as_array_mut) {
        let mut sealed = Vec::new();
        for v in values.iter() {
            let name = v["name"].as_str().unwrap_or_default();
            let raw = v["value_b64"].as_str().unwrap_or_default();
            let bytes = B64.decode(raw).unwrap_or_default();
            let ct = encrypt_part(&ck, &format!("secret:{name}"), 0, &bytes)?;
            sealed.push(json!({"name": name, "box": B64.encode(ct)}));
        }
        manifest["secrets"] = Value::Array(sealed);
        manifest.as_object_mut().map(|o| o.remove("secret_values"));
    }
    let mut dir = Vec::with_capacity(files.len());
    let mut entries = Vec::with_capacity(files.len());
    for (name, bytes) in files {
        let teile: Vec<&[u8]> = if bytes.is_empty() {
            vec![&bytes[..]]
        } else {
            bytes.chunks(CONTAINER_CHUNK).collect()
        };
        let mut chunks = Vec::with_capacity(teile.len());
        for (i, teil) in teile.iter().enumerate() {
            let ct = encrypt_part(&ck, &aad(name), i as u64, teil)?;
            chunks.push(json!({"i": i, "ct": B64.encode(ct)}));
        }
        dir.push(json!({"name": name, "chunks": chunks}));
        let sha = hex::encode(Sha256::digest(bytes));
        // Vorhandene Manifest-Eintraege BEHALTEN (Hash-Kette bleibt), nur
        // sha/bytes aktualisieren; neue Dateien anhaengen.
        let mut entry = json!({"name": name, "sha256": sha, "bytes": bytes.len()});
        if let Some(old) = manifest["files"]
            .as_array()
            .and_then(|a| a.iter().find(|e| e["name"].as_str() == Some(name.as_str())))
        {
            if let Some(chain) = old.get("chain") {
                entry["chain"] = chain.clone();
            }
        }
        entries.push(entry);
    }
    if manifest.get("files").and_then(Value::as_array).is_none() {
        manifest["files"] = Value::Array(entries);
    } else {
        let old = manifest["files"].as_array().cloned().unwrap_or_default();
        let mut merged = Vec::new();
        for e in old {
            let name = e["name"].as_str().unwrap_or_default().to_string();
            if let Some(new) = entries.iter().find(|n| n["name"].as_str() == Some(name.as_str())) {
                merged.push(new.clone());
            }
        }
        for n in entries {
            if !merged.iter().any(|m| m["name"] == n["name"]) {
                merged.push(n);
            }
        }
        manifest["files"] = Value::Array(merged);
    }
    let key_box = seal_container_key(mode, &ck, "z8-export-container").map_err(err_from)?;
    let container = json!({
        "format": CONTAINER_FORMAT,
        "manifest": manifest,
        "files": dir,
        "key_box": key_box,
    });
    let bytes = serde_json::to_vec(&container).map_err(|e| DbError::new("JSON", e.to_string()))?;
    Ok((bytes, manifest))
}

/// Oeffnet den Container, prueft jede Datei gegen das Manifest und liefert
/// (Manifest, Verzeichnis). Falscher Key/Password = Fehler.
pub fn open(container: &[u8], mode: OpenBox<'_>) -> DbResult<(Value, Vec<(String, Vec<u8>)>)> {
    let v: Value =
        serde_json::from_slice(container).map_err(|e| DbError::new("JSON", e.to_string()))?;
    if v["format"].as_str() != Some(CONTAINER_FORMAT) {
        return Err(DbError::new("EXPORT_CONTAINER", "unbekanntes Container-Format"));
    }
    let manifest = v["manifest"].clone();
    let ck = open_container_key(&v["key_box"], mode).map_err(err_from)?;
    let mut out = Vec::new();
    let Some(files) = v["files"].as_array() else {
        return Err(DbError::new("EXPORT_CONTAINER", "files fehlt"));
    };
    for f in files {
        let name = f["name"].as_str().unwrap_or_default().to_string();
        let mut chunks: Vec<(u64, String)> = f["chunks"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|c| {
                        (
                            c["i"].as_u64().unwrap_or(u64::MAX),
                            c["ct"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        chunks.sort_by_key(|c| c.0);
        let mut bytes = Vec::new();
        for (pos, (i, ct)) in chunks.iter().enumerate() {
            if *i != pos as u64 {
                return Err(DbError::new(
                    "EXPORT_CONTAINER",
                    "Chunk-Reihenfolge/Luecke manipuliert",
                ));
            }
            let sealed = B64
                .decode(ct)
                .map_err(|e| DbError::new("EXPORT_CONTAINER", format!("chunk base64: {e}")))?;
            bytes.extend_from_slice(&decrypt_part(&ck, &aad(&name), *i, &sealed)?);
        }
        verify_entry(&manifest, &name, &bytes)?;
        out.push((name, bytes));
    }
    Ok((manifest, out))
}

fn verify_entry(manifest: &Value, name: &str, bytes: &[u8]) -> DbResult<()> {
    let entry = manifest["files"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"].as_str() == Some(name)))
        .ok_or_else(|| DbError::new("EXPORT_INTEGRITY", format!("Manifest-Eintrag fehlt: {name}")))?;
    let sha = hex::encode(Sha256::digest(bytes));
    if entry["sha256"].as_str() != Some(sha.as_str())
        || entry["bytes"].as_u64() != Some(bytes.len() as u64)
    {
        return Err(DbError::new(
            "EXPORT_INTEGRITY",
            format!("SHA256/Groesse stimmt nicht: {name}"),
        ));
    }
    Ok(())
}
