//! WASMI-App-Laufzeit IM Browser-Worker.
//!
//! Identischer KvApp-Vertrag wie nativ: `z8_alloc` / `z8_process`, Payload
//! JSON rein, JSON raus. KEINE Host-Imports -> eine App mit fs/net-Import
//! scheitert bereits bei der Instanziierung (Sandbox wie nativ).

use proxy_kern::{AppInfo, AppReply, ProxyError};
use serde_json::Value;
use wasmi::{Engine, Instance, Linker, Memory, Module, Store};

const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_OUT: usize = 4 * 1024 * 1024;

pub struct WasmiApp {
    pub name: String,
    pub version: String,
    wasm: Vec<u8>,
}

impl WasmiApp {
    pub fn load(name: &str, version: &str, wasm: &[u8]) -> Result<Self, ProxyError> {
        let app = Self {
            name: name.to_string(),
            version: version.to_string(),
            wasm: wasm.to_vec(),
        };
        // Validierung + Instanziierung sofort: Importe ohne Capability trapen.
        app.instantiate()?;
        Ok(app)
    }

    fn instantiate(&self) -> Result<(Store<()>, Instance, Memory), ProxyError> {
        let engine = Engine::default();
        let module = Module::new(&engine, &self.wasm[..])
            .map_err(|e| ProxyError::Wasm(format!("Module: {e}")))?;
        let mut store = Store::new(&engine, ());
        let linker = Linker::<()>::new(&engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| ProxyError::Wasm(format!("Instantiate/Import: {e}")))?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| ProxyError::Wasm("App exportiert keine memory".into()))?;
        Ok((store, instance, memory))
    }

    pub fn info(&self) -> AppInfo {
        AppInfo {
            name: self.name.clone(),
            version: self.version.clone(),
            capabilities: Vec::new(),
            stream: false,
        }
    }

    pub fn call(&self, input: &Value) -> Result<AppReply, ProxyError> {
        let payload = serde_json::to_vec(input)
            .map_err(|e| ProxyError::Wasm(format!("Input serialisieren: {e}")))?;
        if payload.len() > MAX_PAYLOAD {
            return Err(ProxyError::Wasm("App-Input zu gross".into()));
        }
        let (mut store, instance, memory) = self.instantiate()?;
        let alloc = instance
            .get_typed_func::<(i32,), i32>(&store, "z8_alloc")
            .map_err(|e| ProxyError::Wasm(format!("z8_alloc: {e}")))?;
        let process = instance
            .get_typed_func::<(i32, i32), i32>(&store, "z8_process")
            .map_err(|e| ProxyError::Wasm(format!("z8_process: {e}")))?;
        let ptr = alloc
            .call(&mut store, (payload.len() as i32,))
            .map_err(|e| ProxyError::Wasm(format!("alloc trap: {e}")))?;
        if ptr < 0 {
            return Err(ProxyError::Wasm("z8_alloc verweigert".into()));
        }
        memory
            .write(&mut store, ptr as usize, &payload)
            .map_err(|e| ProxyError::Wasm(format!("memory write: {e}")))?;
        let out = process
            .call(&mut store, (ptr, payload.len() as i32))
            .map_err(|e| ProxyError::Wasm(format!("process trap: {e}")))?;
        if out < 0 {
            return Err(ProxyError::Wasm("z8_process verweigert".into()));
        }
        let mut lenb = [0u8; 4];
        memory
            .read(&store, out as usize, &mut lenb)
            .map_err(|e| ProxyError::Wasm(format!("Laenge lesen: {e}")))?;
        let n = u32::from_le_bytes(lenb) as usize;
        if n == 0 || n > MAX_OUT {
            return Err(ProxyError::Wasm(format!("Antwort-Laenge ungueltig: {n}")));
        }
        let mut buf = vec![0u8; n];
        memory
            .read(&store, out as usize + 4, &mut buf)
            .map_err(|e| ProxyError::Wasm(format!("Antwort lesen: {e}")))?;
        let value: Value = serde_json::from_slice(&buf)
            .map_err(|e| ProxyError::Wasm(format!("App-Antwort kein JSON: {e}")))?;
        Ok(AppReply::json(value))
    }
}

/// Test-Naht: beliebiges App-WASM gegen denselben Host fahren (Trap-Beweis).
pub fn call_bytes(wasm: &[u8], input: &Value) -> Result<Value, ProxyError> {
    let app = WasmiApp::load("inline", "0", wasm)?;
    Ok(app.call(input)?.payload)
}
