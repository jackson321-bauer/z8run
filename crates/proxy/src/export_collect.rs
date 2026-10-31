//! Datensammlung des Gesamt-Exports (hinter der Freeze-Reservierung).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use proxy_kern::ProxyError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use z8run_core::dbnode::BoxMode;

use crate::export_worlds::{chain, jsonl, matches, rows, ExportRequest, World};
use crate::service::ProxyService;

impl ProxyService {
    pub(crate) async fn export_collect(
        &self,
        req: &ExportRequest,
        worlds: &[World],
        db: &str,
        freeze: Value,
    ) -> Result<Value, ProxyError> {
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut counts = serde_json::Map::new();

        for w in worlds {
            match w {
                World::Otel => {
                    let spans = match &self.otel {
                        Some(o) => o.all().await?,
                        None => Vec::new(),
                    };
                    let list: Vec<Value> = spans
                        .into_iter()
                        .filter_map(|s| serde_json::to_value(&s).ok())
                        .filter(|v| matches(v, &req.sessions, req.from_ms, req.to_ms))
                        .collect();
                    counts.insert("otel".into(), list.len().into());
                    files.push(("spans.jsonl".into(), jsonl(&list)));
                }
                World::Meta => {
                    let metas = match &self.meta {
                        Some(m) => m.query(None, None, 1_000_000).await?,
                        None => Vec::new(),
                    };
                    let list: Vec<Value> = metas
                        .iter()
                        .filter_map(|m| serde_json::to_value(m).ok())
                        .filter(|v| matches(v, &req.sessions, req.from_ms, req.to_ms))
                        .collect();
                    counts.insert("meta".into(), list.len().into());
                    files.push(("meta.jsonl".into(), jsonl(&list)));
                }
                World::Linefs => {
                    let mut list = rows(self, db, "SELECT * FROM dateien").await;
                    list.extend(rows(self, db, "SELECT * FROM ordner").await);
                    list.extend(rows(self, db, "SELECT * FROM zeilen_epochen").await);
                    let list: Vec<Value> = list
                        .into_iter()
                        .filter(|v| matches(v, &req.sessions, req.from_ms, req.to_ms))
                        .collect();
                    counts.insert("linefs".into(), list.len().into());
                    files.push(("linefs.jsonl".into(), jsonl(&list)));
                }
                World::Flows => {
                    let list: Vec<Value> = rows(self, db, "SELECT * FROM flows")
                        .await
                        .into_iter()
                        .filter(|v| matches(v, &req.sessions, req.from_ms, req.to_ms))
                        .collect();
                    counts.insert("flows".into(), list.len().into());
                    files.push(("flows.jsonl".into(), jsonl(&list)));
                }
                World::Apps => {
                    let list: Vec<Value> = rows(self, db, "SELECT * FROM apps")
                        .await
                        .into_iter()
                        .filter(|v| matches(v, &req.sessions, req.from_ms, req.to_ms))
                        .collect();
                    counts.insert("apps".into(), list.len().into());
                    files.push(("apps.jsonl".into(), jsonl(&list)));
                }
                World::Blobs => {
                    let listed = self
                        .db
                        .blob_session_list(&db)
                        .await
                        .unwrap_or(Value::Null);
                    let mut metas = Vec::new();
                    for m in listed.as_array().cloned().unwrap_or_default() {
                        if !matches(&m, &req.sessions, req.from_ms, req.to_ms) {
                            continue;
                        }
                        let sid = m["session_id"].as_str().unwrap_or_default();
                        let owner = m["owner"].as_str().unwrap_or("export");
                        let bytes = match self.db.blob_session_get(&db, owner, sid).await {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(sid, error = %e, "Export: Blob fehlt");
                                continue;
                            }
                        };
                        files.push((format!("blobs/{sid}.bin"), bytes));
                        metas.push(m);
                    }
                    counts.insert("blobs".into(), metas.len().into());
                    files.push(("blobs.jsonl".into(), jsonl(&metas)));
                }
            }
        }

        // Secrets: Klartext bleibt im Speicher; der Container ersetzt
        // `secret_values` durch versiegelte Huellen (nur Name + Box).
        let secret_values: Vec<Value> = self
            .secrets
            .refs()
            .iter()
            .map(|name| {
                let value = self
                    .secrets
                    .get(name)
                    .map(|v| B64.encode(v.as_bytes()))
                    .unwrap_or_default();
                json!({"name": name, "value_b64": value})
            })
            .collect();
        let mut entries: Vec<Value> = files
            .iter()
            .map(|(name, bytes)| {
                json!({
                    "name": name,
                    "sha256": hex::encode(Sha256::digest(bytes)),
                    "bytes": bytes.len(),
                })
            })
            .collect();
        let chain_head = chain(&mut entries);
        let manifest = json!({
            "version": 1,
            "created_ms": self.now_ms(),
            "wal_stand": freeze,
            "selection": {
                "worlds": worlds.iter().map(|w| format!("{w:?}").to_lowercase()).collect::<Vec<_>>(),
                "db_id": db,
                "sessions": req.sessions,
                "from_ms": req.from_ms,
                "to_ms": req.to_ms,
            },
            "counts": Value::Object(counts),
            "files": entries,
            "hash_chain": chain_head,
            "secret_values": secret_values,
        });
        let mode = match (&req.recipient_pub_b64, &req.recipient_kem_ek_b64) {
            (Some(pub_b64), Some(ek)) => BoxMode::Pqc { pub_b64, kem_ek_b64: ek },
            _ => BoxMode::Password { passwort: &req.password },
        };
        let (container, manifest) =
            z8run_core::dbnode::seal_export_container(&files, manifest, mode)
                .map_err(|e| ProxyError::Internal(format!("Export-Container: {e}")))?;
        self.record_meta(
            "app",
            proxy_kern::meta::EventKind::AppCall,
            db,
            "",
            &format!("export:{}", manifest["hash_chain"].as_str().unwrap_or("")),
            "ok",
            "export_all",
        )
        .await;
        Ok(json!({
            "manifest": manifest,
            "container_b64": B64.encode(container),
        }))
    }
}