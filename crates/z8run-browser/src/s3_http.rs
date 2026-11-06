//! S3-Egress IM Worker-Isolat: SigV4 in Rust, genau EIN fetch-Exit.
//! Nimmt die vom kv-wasm gebaute Vorlage (nur Platzhalter) entgegen,
//! loest {{S3_URL_n}} gegen die Session-Provider auf und fuehrt aus.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};

use crate::opfs;
use crate::sigv4::Signer;

fn amz_date_now() -> String {
    let iso = js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default();
    let d: String = iso.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() >= 14 {
        format!("{}T{}Z", &d[..8], &d[8..14])
    } else {
        "19700101T000000Z".to_string()
    }
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn pct_path(s: &str) -> String {
    s.split('/').map(pct).collect::<Vec<_>>().join("/")
}

async fn fetch(method: &str, url: &str, headers: &[(String, String)], body: Option<Vec<u8>>)
    -> Result<(u16, Vec<u8>), String> {
    let obj = js_sys::Object::new();
    for (k, v) in headers {
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v));
    }
    let b = match body {
        Some(v) => JsValue::from(js_sys::Uint8Array::from(v.as_slice())),
        None => JsValue::NULL,
    };
    let res = wasm_bindgen_futures::JsFuture::from(opfs::fetch(url, method, obj.into(), b))
        .await
        .map_err(|e| format!("fetch: {e:?}"))?;
    let status = js_sys::Reflect::get(&res, &JsValue::from_str("status"))
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as u16;
    let bytes = js_sys::Reflect::get(&res, &JsValue::from_str("bytes"))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Uint8Array>().ok())
        .map(|a| a.to_vec())
        .unwrap_or_default();
    Ok((status, bytes))
}

fn provider<'a>(providers: &'a Value, n: u64) -> Result<&'a Value, String> {
    providers
        .get((n.saturating_sub(1)) as usize)
        .ok_or_else(|| format!("Provider {n} fehlt"))
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn tag<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let a = block.find(&open)? + open.len();
    let b = block[a..].find(&close)? + a;
    Some(&block[a..b])
}

fn parse_list(xml: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for teil in xml.split("<Contents>").skip(1) {
        let block = teil.split("</Contents>").next().unwrap_or(teil);
        let Some(key) = tag(block, "Key") else { continue };
        let size = tag(block, "Size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        out.push(json!({"key": unescape(key), "size": size}));
    }
    out
}

/// Fuehrt EINE kv-Vorlage aus (params enthalten nur Platzhalter).
pub async fn ausfuehren(befehl: &str, p: &Value, providers: &Value) -> Value {
    let n = p["provider"].as_u64().unwrap_or(1);
    let prov = match provider(providers, n) {
        Ok(v) => v,
        Err(e) => return json!({"status": 400, "fehler": e}),
    };
    let endpoint = p["endpoint"].as_str().unwrap_or("");
    if endpoint.contains("://") {
        return json!({"status": 400, "fehler": "Literal-URL verboten"});
    }
    let roh = prov["endpoint"].as_str().unwrap_or("");
    let host = roh
        .strip_prefix("https://")
        .or_else(|| roh.strip_prefix("http://"))
        .unwrap_or(roh)
        .trim_end_matches('/')
        .to_string();
    if host.is_empty() {
        return json!({"status": 400, "fehler": "Provider-Endpoint fehlt"});
    }
    let region = p["region"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| prov["region"].as_str())
        .unwrap_or("us-east-1")
        .to_string();
    let access = prov["access_key"].as_str().unwrap_or("");
    let secret = prov["secret_key"].as_str().unwrap_or("");
    let bucket = p["bucket"].as_str().unwrap_or("");
    if bucket.is_empty() || access.is_empty() {
        return json!({"status": 400, "fehler": "Bucket/Key fehlt"});
    }
    let key = p["key"].as_str().unwrap_or("");
    let prefix = p["prefix"].as_str().unwrap_or("");

    let (methode, path, query, body) = match befehl {
        "s3.getlist" => {
            let mut q = String::from("list-type=2&max-keys=1000");
            if !prefix.is_empty() {
                q.push_str(&format!("&prefix={}", pct(prefix)));
            }
            ("GET", format!("/{bucket}"), q, None)
        }
        "s3.get" | "s3.head" | "s3.delete" => (
            if befehl == "s3.get" { "GET" } else if befehl == "s3.head" { "HEAD" } else { "DELETE" },
            format!("/{bucket}/{}", pct_path(key)),
            String::new(),
            None,
        ),
        "s3.put" | "s3.claim" => {
            let b = match (p["body"].as_str(), p["body_b64"].as_str()) {
                (Some(s), _) => s.as_bytes().to_vec(),
                (_, Some(s)) => match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD, s) {
                    Ok(v) => v,
                    Err(_) => return json!({"status": 400, "fehler": "body_b64 ungueltig"}),
                },
                _ => Vec::new(),
            };
            ("PUT", format!("/{bucket}/{}", pct_path(key)), String::new(), Some(b))
        }
        _ => return json!({"status": 400, "fehler": format!("Befehl nicht erlaubt: {befehl}")}),
    };

    let payload = body.clone().unwrap_or_default();
    let empty = Signer::payload_hash(b"");
    let ph = if payload.is_empty() { empty } else { Signer::payload_hash(&payload) };
    let mut hdrs: Vec<(String, String)> = Vec::new();
    if let Some(ct) = p["content_type"].as_str().filter(|s| !s.is_empty()) {
        hdrs.push(("content-type".into(), ct.into()));
    }
    if befehl == "s3.claim" {
        hdrs.push(("if-none-match".into(), "*".into()));
    }
    if let Some(obj) = p["headers"].as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                hdrs.push((k.clone(), s.to_string()));
            }
        }
    }
    let amz = amz_date_now();
    let signer = Signer::new(access, secret, &region);
    let (_sig, out) = signer.authorization(methode, &host, &path, &query, &hdrs, &ph, &amz);
    let url = if query.is_empty() {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}{path}?{query}")
    };
    match fetch(methode, &url, &out, body).await {
        Err(e) => json!({"status": 0, "befehl": befehl, "fehler": e}),
        Ok((status, bytes)) => {
            if befehl == "s3.getlist" {
                let xml = String::from_utf8_lossy(&bytes).to_string();
                let objekte = parse_list(&xml);
                json!({"status": status, "befehl": befehl,
                       "anzahl": objekte.len(), "objects": objekte})
            } else if befehl == "s3.get" {
                json!({"status": status, "befehl": befehl, "size": bytes.len(),
                       "sha256": hex::encode(Sha256::digest(&bytes))})
            } else {
                json!({"status": status, "befehl": befehl})
            }
        }
    }
}
