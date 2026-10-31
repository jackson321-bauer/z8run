//! Plugin-Bundle-Import: manifest + app.wasm + prompts.enc. Die Prompts
//! werden mit dem DB-Siegel (derselben AEAD+HMAC-Krypto) versiegelt und
//! nur im RAM (Zeroize) gehalten.

use base64::Engine as _;
use proxy_kern::{ProxyError, StoragePort};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use z8run_core::dbnode::crypto::{self, KeyEnvelope};

use crate::adapters::wasm::WasmKvApp;
use crate::service::ProxyService;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub name: String,
    pub version: String,
    #[serde(default = "default_app")]
    pub app: String,
    #[serde(default = "default_prompts")]
    pub prompts: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn default_app() -> String {
    "app.wasm".into()
}
fn default_prompts() -> String {
    "prompts.enc".into()
}

pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub wasm: Vec<u8>,
    pub prompts_sealed: Option<Vec<u8>>,
}

fn key(prefix: &str, file: &str) -> String {
    if prefix.trim_matches('/').is_empty() {
        file.to_string()
    } else {
        format!("{}/{}", prefix.trim_matches('/'), file)
    }
}

pub async fn load_bundle(
    storage: &dyn StoragePort,
    prefix: &str,
) -> Result<LoadedBundle, ProxyError> {
    let manifest_raw = storage
        .read(&key(prefix, "manifest.json"))
        .await?
        .ok_or_else(|| ProxyError::Bundle("manifest.json fehlt".into()))?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_raw)
        .map_err(|e| ProxyError::Bundle(format!("manifest.json: {e}")))?;
    if manifest.name.is_empty() || manifest.version.is_empty() {
        return Err(ProxyError::Bundle("name/version fehlt".into()));
    }
    let wasm = storage
        .read(&key(prefix, &manifest.app))
        .await?
        .ok_or_else(|| ProxyError::Bundle(format!("{} fehlt", manifest.app)))?;
    if wasm.is_empty() {
        return Err(ProxyError::Bundle("app.wasm leer".into()));
    }
    let prompts_sealed = storage.read(&key(prefix, &manifest.prompts)).await?;
    Ok(LoadedBundle {
        manifest,
        wasm,
        prompts_sealed,
    })
}

/// Oeffnet prompts.enc mit dem DB-Siegel. Falscher Key => SIGNATUR-Fehler.
pub fn open_prompts(
    bundle_key: &[u8],
    bundle_id: &str,
    sealed: &[u8],
) -> Result<Vec<(String, Vec<u8>)>, ProxyError> {
    let env = KeyEnvelope::derive(bundle_key, bundle_id)
        .map_err(|e| ProxyError::Bundle(format!("Bundle-Key: {}", e.message)))?;
    let plain = Zeroizing::new(
        crypto::open(&env, bundle_id, 1, "", sealed)
            .map_err(|e| ProxyError::Bundle(format!("Siegel: {}", e.message)))?,
    );
    let text = core::str::from_utf8(&plain)
        .map_err(|e| ProxyError::Bundle(format!("prompts.enc kein UTF-8: {e}")))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, b64) = line
            .split_once('\t')
            .ok_or_else(|| ProxyError::Bundle("Prompt-Zeile ohne Tab".into()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| ProxyError::Bundle(format!("Prompt {name}: {e}")))?;
        out.push((name.to_string(), bytes));
    }
    Ok(out)
}

/// Erzeugt ein versiegeltes prompts.enc (Deploy/Test).
pub fn seal_prompts(
    bundle_key: &[u8],
    bundle_id: &str,
    prompts: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, ProxyError> {
    let mut plain = String::new();
    for (name, text) in prompts {
        plain.push_str(name);
        plain.push('\t');
        plain.push_str(&base64::engine::general_purpose::STANDARD.encode(text));
        plain.push('\n');
    }
    let env = KeyEnvelope::derive(bundle_key, bundle_id)
        .map_err(|e| ProxyError::Bundle(format!("Bundle-Key: {}", e.message)))?;
    crypto::seal(&env, bundle_id, 1, "", plain.as_bytes())
        .map_err(|e| ProxyError::Bundle(format!("Siegel: {}", e.message)))
}

/// Laedt das Bundle in den laufenden Dienst (App + Prompts).
pub async fn bootstrap(
    svc: &ProxyService,
    storage: &dyn StoragePort,
    prefix: &str,
    bundle_key: Option<&[u8]>,
) -> Result<LoadedBundle, ProxyError> {
    let bundle = load_bundle(storage, prefix).await?;
    let app = WasmKvApp::load(
        &bundle.manifest.name,
        &bundle.manifest.version,
        &bundle.wasm,
        bundle.manifest.capabilities.clone(),
    )?;
    svc.apps.register(std::sync::Arc::new(app));
    if let Some(sealed) = &bundle.prompts_sealed {
        match bundle_key.filter(|k| !k.is_empty()) {
            Some(k) => {
                for (name, text) in open_prompts(k, &bundle.manifest.name, sealed)? {
                    svc.prompts.insert(&name, text);
                }
            }
            None => tracing::warn!("prompts.enc vorhanden, aber kein KV_PROXY_BUNDLE_KEY"),
        }
    }
    tracing::info!(
        app = %bundle.manifest.name,
        version = %bundle.manifest.version,
        prompts = svc.prompts.len(),
        "Plugin-Bundle importiert"
    );
    Ok(bundle)
}
