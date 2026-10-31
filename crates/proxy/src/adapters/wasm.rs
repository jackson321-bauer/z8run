//! WASM-App-Adapter: KvApp v0 auf der vorhandenen z8run-runtime-Sandbox.
//! KEINE Host-Imports: keine fs-/net-/clock-Capability fuer Apps.

use std::sync::Mutex;

use proxy_kern::{AppInfo, AppReply, KvApp, ProxyError};
use serde_json::Value;
use z8run_runtime::sandbox::WasmInstance;
use z8run_runtime::{SandboxConfig, WasmSandbox};

pub struct WasmKvApp {
    name: String,
    version: String,
    sandbox: WasmSandbox,
    module: wasmtime::Module,
    instance: Mutex<Option<WasmInstance>>,
    capabilities: Vec<String>,
}

impl WasmKvApp {
    pub fn load(
        name: &str,
        version: &str,
        wasm: &[u8],
        capabilities: Vec<String>,
    ) -> Result<Self, ProxyError> {
        let sandbox = WasmSandbox::new(SandboxConfig::default()).map_err(wasm_err)?;
        let module = sandbox.compile(wasm).map_err(wasm_err)?;
        let app = Self {
            name: name.to_string(),
            version: version.to_string(),
            sandbox,
            module,
            instance: Mutex::new(None),
            capabilities,
        };
        app.init()?;
        Ok(app)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<WasmInstance>> {
        self.instance.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn wasm_err(e: z8run_runtime::RuntimeError) -> ProxyError {
    ProxyError::Wasm(e.to_string())
}

impl KvApp for WasmKvApp {
    fn name(&self) -> &str {
        &self.name
    }

    fn info(&self) -> AppInfo {
        AppInfo {
            name: self.name.clone(),
            version: self.version.clone(),
            capabilities: self.capabilities.clone(),
            stream: true,
        }
    }

    fn init(&self) -> Result<(), ProxyError> {
        let mut guard = self.lock();
        if guard.is_none() {
            *guard = Some(
                self.sandbox
                    .instantiate_module(&self.module)
                    .map_err(wasm_err)?,
            );
        }
        Ok(())
    }

    fn handle(&self, input: &Value) -> Result<AppReply, ProxyError> {
        let payload = serde_json::to_string(input)
            .map_err(|e| ProxyError::Wasm(format!("Input serialisieren: {e}")))?;
        let mut guard = self.lock();
        if guard.is_none() {
            *guard = Some(
                self.sandbox
                    .instantiate_module(&self.module)
                    .map_err(wasm_err)?,
            );
        }
        let instance = guard.as_mut().expect("instanz vorhanden");
        match instance.call_process(&payload) {
            Ok(out) => {
                let value: Value = serde_json::from_str(&out)
                    .map_err(|e| ProxyError::Wasm(format!("App-Antwort kein JSON: {e}")))?;
                Ok(AppReply::json(value))
            }
            Err(e) => {
                // Instanz verwerfen: Speicher kann inkonsistent sein.
                *guard = None;
                Err(ProxyError::Wasm(e.to_string()))
            }
        }
    }

    fn cleanup(&self) -> Result<(), ProxyError> {
        *self.lock() = None;
        Ok(())
    }
}
