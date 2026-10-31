//! Platzhalter-Injektion am Ausgang (F10): Systemprompts + Variablen + Keys
//! stehen als `{{secret:ns/name}}` im Text und werden erst am LLM-/API-
//! Ausgang aus dem versiegelten Store eingesetzt. Klartext wird nach dem
//! Senden geschreddert (zeroize). Logs/Spans/ Antworten sehen NIE den Wert —
//! nur Referenz + sha256-Hash (tresor-proxy-Regel).

use std::collections::HashMap;
use std::sync::Mutex;

use proxy_kern::ProxyError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub namespace: String,
    pub name: String,
}

impl SecretRef {
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Default)]
pub struct SecretStore {
    map: Mutex<HashMap<String, Zeroizing<String>>>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Aus JSON `{"ns/name": "wert"}` (z.B. entsiegelt aus dem Store).
    pub fn from_json(json: &str) -> Result<Self, ProxyError> {
        let map: HashMap<String, String> = serde_json::from_str(json)
            .map_err(|e| ProxyError::BadRequest(format!("Secret-Store JSON: {e}")))?;
        let store = Self::new();
        for (k, v) in map {
            let (ns, name) = k
                .split_once('/')
                .ok_or_else(|| ProxyError::BadRequest(format!("Secret-Key ohne ns/: {k}")))?;
            store.insert(ns, name, &v);
        }
        Ok(store)
    }

    pub fn insert(&self, namespace: &str, name: &str, value: &str) {
        let key = format!("{namespace}/{name}");
        self.lock()
            .insert(key, Zeroizing::new(value.to_string()));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<String>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn contains(&self, namespace: &str, name: &str) -> bool {
        self.lock().contains_key(&format!("{namespace}/{name}"))
    }

    /// Liefert den Wert kopiert (zeroize). Nur fuer Redaktion am Ausgang.
    pub fn get(&self, key: &str) -> Option<Zeroizing<String>> {
        self.lock().get(key).map(|v| Zeroizing::new(v.to_string()))
    }

    pub fn refs(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lock().keys().cloned().collect();
        v.sort();
        v
    }

    /// Setzt alle Platzhalter ein. Liefert Klartext (zeroize beim Drop),
    /// die verwendeten Referenzen und deren Hashes (fuer Logs).
    pub fn inject(&self, template: &str) -> Result<Injected, ProxyError> {
        let mut text = String::with_capacity(template.len());
        let mut refs = Vec::new();
        let mut hashes = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find("{{secret:") {
            text.push_str(&rest[..start]);
            let after = &rest[start + "{{secret:".len()..];
            let end = after.find("}}").ok_or_else(|| {
                ProxyError::BadRequest("Platzhalter ohne schliessendes }}".into())
            })?;
            let key = after[..end].trim();
            let value = self.lock().get(key).cloned().ok_or_else(|| {
                ProxyError::NotFound(format!("secret {key}"))
            })?;
            refs.push(key.to_string());
            hashes.push(hash_secret(value.as_str()));
            text.push_str(value.as_str());
            rest = &after[end + 2..];
        }
        text.push_str(rest);
        Ok(Injected {
            text: Zeroizing::new(text),
            refs,
            hashes,
        })
    }
}

pub struct Injected {
    pub text: Zeroizing<String>,
    pub refs: Vec<String>,
    pub hashes: Vec<String>,
}

/// Nur fuer Logs: Hash eines Secret-Werts (nie der Wert selbst).
pub fn hash_secret(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

/// Sammelt Platzhalter-Referenzen aus einem Text (ohne Werte zu beruehren).
pub fn placeholders(template: &str) -> Vec<SecretRef> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{secret:") {
        let after = &rest[start + "{{secret:".len()..];
        let Some(end) = after.find("}}") else { break };
        let key = after[..end].trim();
        if let Some((ns, name)) = key.split_once('/') {
            out.push(SecretRef {
                namespace: ns.to_string(),
                name: name.to_string(),
            });
        }
        rest = &after[end + 2..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injiziert_und_loggt_nur_hash() {
        let s = SecretStore::new();
        s.insert("ncp", "api_key", "SK-GEHEIM-123");
        let out = s
            .inject("Key={{secret:ncp/api_key}}; Ende")
            .unwrap();
        assert_eq!(out.text.as_str(), "Key=SK-GEHEIM-123; Ende");
        assert_eq!(out.refs, vec!["ncp/api_key"]);
        assert_ne!(out.hashes[0], "SK-GEHEIM-123");
        assert_eq!(out.hashes[0], hash_secret("SK-GEHEIM-123"));
    }

    #[test]
    fn fehlender_platzhalter_ist_not_found() {
        let s = SecretStore::new();
        assert!(s.inject("{{secret:x/y}}").is_err());
    }

    #[test]
    fn placeholders_parst_mehrere() {
        let p = placeholders("{{secret:a/b}} und {{secret:c/d}}");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].key(), "a/b");
    }
}
