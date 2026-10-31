//! App-Registry + LLM-Attrappe. Prompts werden nur hier (LLM-Port)
//! injiziert; Apps bekommen nie Prompt-Inhalt.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use proxy_kern::{AppInfo, KvApp, LlmPort, ProxyError};
use serde_json::Value;

#[derive(Default)]
pub struct AppRegistry {
    apps: Mutex<HashMap<String, Arc<dyn KvApp>>>,
}

impl AppRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, app: Arc<dyn KvApp>) {
        self.lock().insert(app.name().to_string(), app);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<dyn KvApp>>> {
        self.apps.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, name: &str) -> Result<Arc<dyn KvApp>, ProxyError> {
        self.lock()
            .get(name)
            .cloned()
            .ok_or_else(|| ProxyError::NotFound(format!("app {name}")))
    }

    pub fn list(&self) -> Vec<AppInfo> {
        let mut v: Vec<AppInfo> = self.lock().values().map(|a| a.info()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// LLM-Attrappe: gibt NIE den Systemprompt zurueck, nur Metadaten.
pub struct MockLlm;

#[async_trait]
impl LlmPort for MockLlm {
    async fn complete(&self, system: &str, user: &str) -> Result<Value, ProxyError> {
        Ok(serde_json::json!({
            "model": "mock",
            "user": user,
            "system_injected": !system.is_empty(),
            "system_chars": system.chars().count(),
        }))
    }
}

/// Entfernt Prompt-Inhalt aus einer LLM-Antwort (Defense-in-Depth).
pub fn redact_value(value: &mut Value, secret: &str) {
    if secret.is_empty() {
        return;
    }
    match value {
        Value::String(s) => {
            if s.contains(secret) {
                *s = s.replace(secret, "[REDACTED]");
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value(item, secret);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                redact_value(v, secret);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_entfernt_prompt_aus_objekt_und_array() {
        let mut v = serde_json::json!({
            "a": "geheim-x",
            "b": ["ok", "auch geheim-x drin"],
            "c": 3
        });
        redact_value(&mut v, "geheim-x");
        let text = v.to_string();
        assert!(!text.contains("geheim-x"));
        assert!(text.contains("[REDACTED]"));
    }
}
