//! One-shot CLI für das MCP-Tool `z8_db`: liest EIN JSON-Objekt von stdin,
//! öffnet die DB (Masterkey aus dem JSON) und führt EINE Aktion aus.
//! Antwort enthält NIE den Masterkey. Kein HTTP, nur lokale Engine.

mod linefs;

use serde_json::{json, Value};
use std::io::Read;
use z8run_core::dbnode::types::DbNodeConfig;
use z8run_core::dbnode::DbNode;
use z8run_core::nodes::dbnode_common::ClusterSpec;

fn b64(raw: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| format!("master_key_b64: {e}"))
}

#[tokio::main]
async fn main() {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        print(&json!({"status": 400, "code": "INPUT", "error": e.to_string()}));
        std::process::exit(2);
    }
    let v: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            print(&json!({"status": 400, "code": "JSON", "error": e.to_string()}));
            std::process::exit(2);
        }
    };
    match run(&v).await {
        Ok(out) => print(&out),
        Err((code, msg)) => {
            print(&json!({"status": 400, "code": code, "error": msg}));
            std::process::exit(1);
        }
    }
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string(v).unwrap_or_else(|_| "{}".into()));
}

async fn run(v: &Value) -> Result<Value, (String, String)> {
    let action = v["action"].as_str().unwrap_or("status").to_string();
    let db_id = v["db_id"].as_str().unwrap_or("default").to_string();
    let master = b64(v["master_key_b64"].as_str().unwrap_or(""))
        .map_err(|e| ("KEY".into(), e))?;
    let spec = ClusterSpec::from_config(v);
    let node = DbNode::new(DbNodeConfig::default());
    let status = node
        .open_db(&db_id, &master, spec.to_cluster())
        .await
        .map_err(|e| (e.code, e.message))?;

    match action.as_str() {
        "open" | "status" => Ok(json!({"status": 200, "db_status": status})),
        "schema" => node
            .schema(&db_id)
            .map(|s| json!({"status": 200, "schema": s}))
            .map_err(|e| (e.code, e.message)),
        "query" => {
            let sql = v["sql"].as_str().unwrap_or("");
            let params = v["params"].as_array().cloned().unwrap_or_default();
            node.query(&db_id, sql, &params)
                .map(|q| json!({"status": 200, "query": q}))
                .map_err(|e| (e.code, e.message))
        }
        "write" => {
            let sql = v["sql"].as_str().unwrap_or("");
            let params = v["params"].as_array().cloned().unwrap_or_default();
            let session = v["session_id"].as_str().unwrap_or("mcp");
            node.reserve(&db_id, session).map_err(|e| (e.code, e.message))?;
            let res = node.write(&db_id, session, sql, params).await;
            let _ = node.release(&db_id, session);
            res.map(|w| json!({"status": 200, "write": w}))
                .map_err(|e| (e.code, e.message))
        }
        "sync" => node
            .wal_sync(&db_id)
            .await
            .map(|p| json!({"status": 200, "progress": p}))
            .map_err(|e| (e.code, e.message)),
        "blob_put" => {
            let session = v["session_id"].as_str().unwrap_or("mcp");
            let owner = v["owner"].as_str().unwrap_or("mcp");
            let name = v["name"].as_str().unwrap_or("blob.bin");
            let mime = v["mime"].as_str().unwrap_or("application/octet-stream");
            node.reserve(&db_id, session).map_err(|e| (e.code, e.message))?;
            let pfad = v["datei_pfad"].as_str().unwrap_or("");
            let res = if !pfad.is_empty() && std::path::Path::new(pfad).is_file() {
                node.blob_put_file(&db_id, session, owner, name, mime, std::path::Path::new(pfad))
                    .await
            } else {
                use base64::Engine;
                let raw = v["base64"].as_str().unwrap_or("");
                match base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
                    Ok(data) => node.blob_put_bytes(&db_id, session, owner, name, mime, &data).await,
                    Err(e) => {
                        let _ = node.release(&db_id, session);
                        return Err(("BLOB_INPUT".into(), format!("base64: {e}")));
                    }
                }
            };
            let _ = node.release(&db_id, session);
            res.map(|m| json!({"status": 200, "blob": m}))
                .map_err(|e| (e.code, e.message))
        }
        "blob_get" => {
            let blob_id = v["blob_id"].as_str().unwrap_or("");
            if blob_id.is_empty() {
                return Err(("BLOB_INPUT".into(), "blob_id fehlt".into()));
            }
            let ziel = v["ziel_adapter"].as_str().unwrap_or("");
            if !ziel.is_empty() {
                node.blob_get_to_file(&db_id, blob_id, std::path::Path::new(ziel))
                    .await
                    .map(|m| json!({"status": 200, "ziel": ziel, "blob": m}))
                    .map_err(|e| (e.code, e.message))
            } else {
                use base64::Engine;
                node.blob_get_bytes(&db_id, blob_id)
                    .await
                    .map(|d| json!({"status": 200, "blob_id": blob_id,
                                    "base64": base64::engine::general_purpose::STANDARD.encode(&d)}))
                    .map_err(|e| (e.code, e.message))
            }
        }
        "blob_list" => node
            .blob_list(&db_id)
            .map(|b| json!({"status": 200, "blobs": b}))
            .map_err(|e| (e.code, e.message)),
        "blob_delete" => {
            let blob_id = v["blob_id"].as_str().unwrap_or("");
            let session = v["session_id"].as_str().unwrap_or("mcp");
            node.reserve(&db_id, session).map_err(|e| (e.code, e.message))?;
            let res = node.blob_delete(&db_id, session, blob_id).await;
            let _ = node.release(&db_id, session);
            res.map(|parts| json!({"status": 200, "blob_id": blob_id, "parts": parts}))
                .map_err(|e| (e.code, e.message))
        }
        "linefs" | "linefs_ops" | "ordner" => {
            let session = v["session_id"].as_str().unwrap_or("mcp");
            linefs::run(&node, &db_id, session, v).await
        }
        other if other.starts_with("linefs_") || other.starts_with("ordner_") => {
            let session = v["session_id"].as_str().unwrap_or("mcp");
            linefs::run(&node, &db_id, session, v).await
        }
        other => Err(("ACTION".into(), format!("unbekannte Aktion: {other}"))),
    }
}
