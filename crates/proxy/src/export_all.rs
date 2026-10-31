//! S5 GESAMT-EXPORT (G12–G15): EINE API mit SELEKTION ueber die Welten.
//! Friert den WAL-Stand N ein, legt JSONL + Binaer-Blobs in einen
//! PQC-Container mit Manifest (sha256 je Datei + Hash-Kette). Secrets
//! wandern NUR als Name + Hash (Huelle) ins Manifest, nie im Klartext.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use proxy_kern::ProxyError;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use z8run_core::dbnode::BoxMode;

use crate::service::ProxyService;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum World {
    Linefs,
    Blobs,
    Otel,
    Meta,
    Flows,
    Apps,
}

const ALL: [World; 6] = [
    World::Linefs,
    World::Blobs,
    World::Otel,
    World::Meta,
    World::Flows,
    World::Apps,
];

#[derive(Debug, Clone, Deserialize)]
pub struct ExportRequest {
    #[serde(default)]
    pub worlds: Vec<World>,
    #[serde(default)]
    pub db_id: Option<String>,
    #[serde(default)]
    pub sessions: Vec<String>,
    #[serde(default)]
    pub from_ms: Option<u64>,
    #[serde(default)]
    pub to_ms: Option<u64>,
    pub password: String,
}

/// Minimaler RFC3339-Parser (LineFS `ts` ist Text, kein ts_ms).
fn rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let n = |a: usize, l: usize| -> Option<i64> { s.get(a..a + l)?.parse().ok() };
    let (y, mo, d) = (n(0, 4)?, n(5, 2)?, n(8, 2)?);
    let (h, mi, se) = (n(11, 2)?, n(14, 2)?, n(17, 2)?);
    // Howard Hinnant, days_from_civil
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3_600 + mi * 60 + se;
    u64::try_from(secs).ok().map(|x| x * 1000)
}

fn pick<'a>(row: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| row.get(*k)).filter(|v| !v.is_null())
}

fn matches(row: &Value, sessions: &[String], from: Option<u64>, to: Option<u64>) -> bool {
    if !sessions.is_empty() {
        let id = pick(row, &["session", "session_id", "owner"])
            .or_else(|| row.get("attrs").and_then(|a| a.get("session")));
        match id.and_then(Value::as_str) {
            Some(s) if sessions.iter().any(|x| x == s) => {}
            _ => return false,
        }
    }
    let ts = pick(row, &["ts_ms", "start_ms", "created_ms", "created_at"])
        .and_then(Value::as_u64)
        .or_else(|| {
            pick(row, &["ts", "created_at"])
                .and_then(Value::as_str)
                .and_then(rfc3339_ms)
        });
    if let Some(t) = ts {
        if from.is_some_and(|f| t < f) || to.is_some_and(|u| t > u) {
            return false;
        }
    }
    true
}

fn jsonl(rows: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for r in rows {
        out.push_str(&serde_json::to_string(r).unwrap_or_else(|_| "null".into()));
        out.push('\n');
    }
    out.into_bytes()
}

fn chain(entries: &mut [Value]) -> String {
    let mut prev = String::new();
    for e in entries.iter_mut() {
        let name = e["name"].as_str().unwrap_or_default();
        let sha = e["sha256"].as_str().unwrap_or_default();
        let mut h = Sha256::new();
        h.update(prev.as_bytes());
        h.update(name.as_bytes());
        h.update(sha.as_bytes());
        prev = hex::encode(h.finalize());
        e["chain"] = Value::from(prev.clone());
    }
    prev
}

async fn rows(svc: &ProxyService, db: &str, sql: &str) -> Vec<Value> {
    match svc.db.query(db, sql, Vec::new(), true).await {
        Ok(v) => {
            // QueryOutcome = {columns, rows:[[..]]} -> JSONL braucht Objekte.
            let cols: Vec<String> = v["columns"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            v["rows"]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .map(|row| {
                            let mut o = serde_json::Map::new();
                            if let Some(vals) = row.as_array() {
                                for (i, c) in cols.iter().enumerate() {
                                    o.insert(c.clone(), vals.get(i).cloned().unwrap_or(Value::Null));
                                }
                            }
                            Value::Object(o)
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
        Err(e) => {
            tracing::warn!(db, sql, error = %e, "Export: Welt nicht lesbar, uebersprungen");
            Vec::new()
        }
    }
}

impl ProxyService {
    pub async fn export_all(&self, req: &ExportRequest) -> Result<Value, ProxyError> {
        let db = req.db_id.clone().unwrap_or_else(|| "demo".to_string());
        let worlds: Vec<World> = if req.worlds.is_empty() {
            ALL.to_vec()
        } else {
            req.worlds.clone()
        };
        // FREEZE: Schreib-Reservierung auf allen beteiligten DBs blockiert
        // jeden Schreiber; DANACH WAL-Stand N lesen. Freigabe immer am Ende.
        let mut ids: Vec<String> = Vec::new();
        if worlds
            .iter()
            .any(|w| matches!(w, World::Linefs | World::Blobs | World::Flows | World::Apps))
        {
            ids.push(db.clone());
        }
        if worlds.contains(&World::Otel) {
            ids.push(self.cfg.otel_db.clone());
        }
        if worlds.contains(&World::Meta) {
            ids.push(self.cfg.meta_db.clone());
            ids.push(self.cfg.cluster_meta_db.clone());
        }
        ids.dedup();
        let mut held: Vec<String> = Vec::new();
        for id in ids {
            if held.contains(&id) {
                continue;
            }
            match self.db.reserve(&id, "export-all").await {
                Ok(_) => held.push(id),
                Err(e) => {
                    for h in &held {
                        let _ = self.db.release(h, "export-all").await;
                    }
                    return Err(ProxyError::Db(format!("Freeze-Reservierung {id}: {e}")));
                }
            }
        }
        let freeze = self.db.status(None).await.unwrap_or(Value::Null);
        let out = self.export_collect(req, &worlds, &db, freeze).await;
        for h in &held {
            let _ = self.db.release(h, "export-all").await;
        }
        out
    }

    async fn export_collect(
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
        let mode = BoxMode::Password {
            passwort: &req.password,
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

/// Oeffnet einen Export-Container (Tests/CLI/Import): Manifest + Verzeichnis.
pub fn open_export(
    container: &[u8],
    passwort: &str,
) -> Result<(Value, Vec<(String, Vec<u8>)>), String> {
    let mode = z8run_core::dbnode::OpenBox::Password { passwort };
    z8run_core::dbnode::open_export_container(container, mode).map_err(|e| e.to_string())
}

/// Hilfsfunktion fuer Clients, die nur den Container weitergeben.
pub fn decode_container(b64: &str) -> Result<Vec<u8>, String> {
    B64.decode(b64).map_err(|e| e.to_string())
}
