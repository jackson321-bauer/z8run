//! Prompt-Store: NUR RAM + versiegelt. Prompt-Inhalt ist nie Teil einer
//! App-Antwort oder eines Debug-/Serialisierungsausgabewerts.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::error::ProxyError;

#[derive(Default)]
pub struct PromptStore {
    prompts: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl fmt::Debug for PromptStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptStore")
            .field("count", &self.names().len())
            .finish()
    }
}

impl PromptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, name: &str, content: Vec<u8>) {
        self.lock().insert(name.to_string(), Zeroizing::new(content));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<Vec<u8>>>> {
        self.prompts.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lock().keys().cloned().collect();
        v.sort();
        v
    }

    pub fn contains(&self, name: &str) -> bool {
        self.lock().contains_key(name)
    }

    /// Liefert eine Kopie im Zeroize-Speicher; der Aufrufer darf sie nur an
    /// den LLM-Port geben, nie an eine App oder in ein Log.
    pub fn get(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, ProxyError> {
        self.lock()
            .get(name)
            .map(|v| Zeroizing::new(v.to_vec()))
            .ok_or_else(|| ProxyError::NotFound(format!("prompt {name}")))
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_zeigt_keinen_prompt_inhalt() {
        let store = PromptStore::new();
        store.insert("sys", b"streng-geheim".to_vec());
        let text = format!("{store:?}");
        assert!(!text.contains("streng-geheim"));
        assert_eq!(store.names(), vec!["sys".to_string()]);
    }

    #[test]
    fn unbekannter_prompt_ist_not_found() {
        let store = PromptStore::new();
        assert!(matches!(
            store.get("fehlt"),
            Err(ProxyError::NotFound(_))
        ));
    }
}
