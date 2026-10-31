//! APP-VERTRAG v0: `KvApp` (init/handle/cleanup). Payload JSON rein,
//! JSON raus + optionaler Stream-Port. Implementierungen: WASM (nativ geladen)
//! oder eingebaute Rust-Apps. Der Vertrag selbst macht kein I/O.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProxyError;

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub stream: bool,
}

#[derive(Debug, Clone)]
pub struct AppReply {
    pub payload: Value,
    /// Optionaler Stream-Port: Rohbytes, die der Proxy chunked/SSE ausgibt.
    pub stream: Option<Vec<u8>>,
}

impl AppReply {
    pub fn json(payload: Value) -> Self {
        Self {
            payload,
            stream: None,
        }
    }
}

/// Anfrage an eine App (wird als JSON an WASM gereicht).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRequest {
    pub op: String,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub stream: bool,
}

pub trait KvApp: Send + Sync {
    fn name(&self) -> &str;
    fn info(&self) -> AppInfo;
    fn init(&self) -> Result<(), ProxyError>;
    fn handle(&self, input: &Value) -> Result<AppReply, ProxyError>;
    fn cleanup(&self) -> Result<(), ProxyError>;
}

/// Ergebnis einer App-Ausfuehrung, wie es der Proxy nach aussen gibt.
/// Enthaelt NIE Prompt-Inhalte: Apps haben keinen Prompt-Store-Zugriff.
#[derive(Debug, Clone, Serialize)]
pub struct AppCallResult {
    pub app: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_len: Option<usize>,
}
