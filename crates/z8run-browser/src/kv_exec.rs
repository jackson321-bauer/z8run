//! kv-store-wasm als Hilfsmodul IM SELBEN Isolat (ausserhalb des Kerns)
//! plus Egress-Orchestrierung: Sync-App -> cmd.kv.* -> kv-wasm-Vorlage ->
//! In-Isolat-Ausfuehrung. Daemon-URLs werden NIE gefetcht; ihre Vorlagen
//! landen als Heft-Events im Isolat. Antworten gehen als result.* zurueck.

use serde_json::{json, Value};

use crate::apps::WasmiApp;
use crate::s3_http;

pub fn kv_aufruf(bytes: &[u8], auftrag: &Value) -> Result<Value, String> {
    let app = WasmiApp::load("kv-wasm", "0.1.0", bytes).map_err(|e| e.to_string())?;
    Ok(app.call(auftrag).map_err(|e| e.to_string())?.payload)
}

fn klass(url: &str) -> &'static str {
    if url.contains("aufgabe") {
        "aufgabe"
    } else if url.contains("alarm") {
        "alarm"
    } else if url.contains("progress") {
        "progress"
    } else if url.contains("sink") {
        "publish"
    } else if url.contains("clone") {
        "auftrag"
    } else {
        "event"
    }
}

fn liste(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Object(_) => vec![v.clone()],
        _ => Vec::new(),
    }
}

pub async fn egress_ausfuehren(
    egress: &Value,
    providers: &Value,
    kv: &[u8],
    _session: &str,
) -> (Vec<Value>, Vec<Value>) {
    let mut results = Vec::new();
    let mut heft = Vec::new();
    for e in liste(egress) {
        let befehl = e["befehl_vorlage"]["befehl"].as_str().unwrap_or("");
        let params = &e["befehl_vorlage"]["params"];
        let corr = e["correlation_id"].as_str().unwrap_or("");
        if befehl.starts_with("s3.") {
            let mut auftrag = params.clone();
            if let Some(o) = auftrag.as_object_mut() {
                o.insert("befehl".into(), json!(befehl));
                o.insert("correlation_id".into(), json!(corr));
            }
            match kv_aufruf(kv, &auftrag) {
                Ok(reply) if reply["ok"] == true => {
                    for t in liste(&reply["egress"]) {
                        let b = t["befehl_vorlage"]["befehl"].as_str().unwrap_or(befehl);
                        let p = &t["befehl_vorlage"]["params"];
                        let mut r = s3_http::ausfuehren(b, p, providers).await;
                        r["via"] = json!("kv-wasm-in-isolat");
                        r["correlation_id"] = json!(corr);
                        results.push(r);
                    }
                }
                Ok(reply) => results.push(json!({
                    "status": 400, "befehl": befehl,
                    "fehler": "kv-wasm verweigerte Vorlage", "kv": reply})),
                Err(e) => results.push(json!({
                    "status": 500, "befehl": befehl, "fehler": e})),
            }
        } else if befehl == "http.post" {
            let url = params["url"].as_str().unwrap_or("");
            let art = klass(url);
            heft.push(json!({
                "art": art, "correlation_id": corr,
                "koerper": params["body"].clone(),
                "ts_ms": js_sys::Date::now() as u64,
            }));
            results.push(json!({
                "status": 200, "befehl": "http.post", "in_isolat": true,
                "heft_event": art, "correlation_id": corr}));
        } else {
            results.push(json!({
                "status": 400, "befehl": befehl,
                "fehler": "Egress-Befehl nicht erlaubt"}));
        }
    }
    (results, heft)
}
