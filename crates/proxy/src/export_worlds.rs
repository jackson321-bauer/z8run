//! Export-Welten, Filter und Zeilen-/Ketten-Helfer (G12–G15).

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

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

pub(crate) const ALL: [World; 6] = [
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
    #[serde(default)]
    pub password: String,
    /// Optionale PQC-Empfaenger-Pyramide (v3). Ohne beide Felder: Passwort.
    #[serde(default)]
    pub recipient_pub_b64: Option<String>,
    #[serde(default)]
    pub recipient_kem_ek_b64: Option<String>,
}

/// Minimaler RFC3339-Parser (LineFS `ts` ist Text, kein ts_ms).
pub(crate) fn rfc3339_ms(s: &str) -> Option<u64> {
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

pub(crate) fn pick<'a>(row: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| row.get(*k)).filter(|v| !v.is_null())
}

pub(crate) fn matches(row: &Value, sessions: &[String], from: Option<u64>, to: Option<u64>) -> bool {
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

pub(crate) fn jsonl(rows: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for r in rows {
        out.push_str(&serde_json::to_string(r).unwrap_or_else(|_| "null".into()));
        out.push('\n');
    }
    out.into_bytes()
}

pub(crate) fn chain(entries: &mut [Value]) -> String {
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

pub(crate) async fn rows(svc: &ProxyService, db: &str, sql: &str) -> Vec<Value> {
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
