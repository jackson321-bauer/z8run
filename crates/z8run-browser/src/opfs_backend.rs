//! OpfsBackend am gemeinsamen `StorageBackend`-Trait (dbnode-Vertrag).
//!
//! Klar getrennt vom DB-Weg: der DB-VFS schreibt Z8FC1 je Datei, dieser
//! Adapter ist die optionale lokale Blob-Cache-Schicht. Er nutzt EINEN
//! SyncAccessHandle-Container (`z8blobs.vfs`) mit Index-Header, damit die
//! Trait-Futures ohne JS-Promise auskommen (Worker-synchron, Send-sicher).

use async_trait::async_trait;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use z8run_core::dbnode_contract_storage::{valid_key, StorageBackend};
use z8run_core::dbnode_contract_types::{DbError, DbResult};

#[wasm_bindgen(inline_js = r#"
export async function z8_vfs_open() {
  if (globalThis.__z8vfs) return true;
  const dir = await navigator.storage.getDirectory();
  const fh = await dir.getFileHandle("z8blobs.vfs", { create: true });
  const sh = await fh.createSyncAccessHandle();
  let idx = {};
  const size = sh.getSize();
  if (size >= 65536) {
    const hdr = new Uint8Array(8);
    sh.read(hdr, { at: 0 });
    const dv = new DataView(hdr.buffer);
    const n = dv.getUint32(0, false);
    if (n > 0 && n < 60000) {
      const b = new Uint8Array(n);
      sh.read(b, { at: 8 });
      try { idx = JSON.parse(new TextDecoder().decode(b)); } catch (e) { idx = {}; }
    }
  }
  if (!idx.__end || idx.__end < 65536) idx.__end = 65536;
  globalThis.__z8vfs = { sh, idx };
  return true;
}
function z8_vfs_hdr() {
  const v = globalThis.__z8vfs;
  const enc = new TextEncoder().encode(JSON.stringify(v.idx));
  const hdr = new Uint8Array(65536);
  const dv = new DataView(hdr.buffer);
  dv.setUint32(0, enc.length, false);
  hdr.set(enc, 8);
  v.sh.write(hdr, { at: 0 });
  v.sh.flush();
}
export function z8_vfs_write(key, bytes) {
  const v = globalThis.__z8vfs;
  if (!v) throw new Error("vfs nicht offen");
  const off = v.idx.__end;
  v.sh.write(bytes, { at: off });
  v.idx[key] = { off, len: bytes.length };
  v.idx.__end = off + bytes.length;
  z8_vfs_hdr();
  return bytes.length;
}
export function z8_vfs_read(key) {
  const v = globalThis.__z8vfs;
  if (!v) throw new Error("vfs nicht offen");
  const e = v.idx[key];
  if (!e) return null;
  const b = new Uint8Array(e.len);
  v.sh.read(b, { at: e.off });
  return b;
}
export function z8_vfs_list(prefix) {
  const v = globalThis.__z8vfs;
  if (!v) throw new Error("vfs nicht offen");
  return Object.keys(v.idx).filter((k) => k !== "__end" && k.startsWith(prefix)).sort();
}
export function z8_vfs_delete(key) {
  const v = globalThis.__z8vfs;
  if (!v) throw new Error("vfs nicht offen");
  if (!(key in v.idx)) return false;
  delete v.idx[key];
  z8_vfs_hdr();
  return true;
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = z8_vfs_open)]
    pub fn vfs_open() -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_vfs_write)]
    fn vfs_write(key: &str, bytes: &[u8]) -> JsValue;
    #[wasm_bindgen(js_name = z8_vfs_read)]
    fn vfs_read(key: &str) -> JsValue;
    #[wasm_bindgen(js_name = z8_vfs_list)]
    fn vfs_list(prefix: &str) -> JsValue;
    #[wasm_bindgen(js_name = z8_vfs_delete)]
    fn vfs_delete(key: &str) -> JsValue;
}

/// Oeffnet den Container einmalig (Worker-Start oder erster Zugriff).
pub async fn init() -> Result<(), String> {
    wasm_bindgen_futures::JsFuture::from(vfs_open())
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

fn bad(e: impl std::fmt::Display) -> DbError {
    DbError::new("OPFS", e.to_string())
}

#[derive(Default, Clone, Copy)]
pub struct OpfsBackend;

fn need_open() -> DbResult<()> {
    let open = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("__z8vfs"))
        .ok()
        .map(|v| !v.is_undefined() && !v.is_null())
        .unwrap_or(false);
    if open {
        Ok(())
    } else {
        Err(bad("vfs nicht offen (init fehlt)"))
    }
}

/// Synchroner Container-Zugriff. Damit koennen auch Send-Futures (DbPort)
/// OPFS nutzen: der SyncAccessHandle arbeitet ohne Promise.
pub fn put_sync(key: &str, data: &[u8]) -> DbResult<()> {
    valid_key(key)?;
    need_open()?;
    let n = vfs_write(key, data);
    if n.as_f64().unwrap_or(0.0) as usize != data.len() {
        return Err(bad("OPFS write unvollstaendig"));
    }
    Ok(())
}

pub fn get_sync(key: &str) -> DbResult<Option<Vec<u8>>> {
    valid_key(key)?;
    need_open()?;
    let v = vfs_read(key);
    if v.is_null() || v.is_undefined() {
        return Ok(None);
    }
    let arr = v.dyn_into::<js_sys::Uint8Array>().map_err(|e| bad(format!("{e:?}")))?;
    Ok(Some(arr.to_vec()))
}

pub fn list_sync(prefix: &str) -> DbResult<Vec<String>> {
    need_open()?;
    let v = vfs_list(prefix);
    let arr = v.dyn_into::<js_sys::Array>().map_err(|e| bad(format!("{e:?}")))?;
    Ok(arr.iter().map(|x| x.as_string().unwrap_or_default()).collect())
}

pub fn delete_sync(key: &str) -> DbResult<()> {
    valid_key(key)?;
    need_open()?;
    let _ = vfs_delete(key);
    Ok(())
}

#[async_trait]
impl StorageBackend for OpfsBackend {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>> {
        get_sync(key)
    }

    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()> {
        put_sync(key, data)
    }

    async fn list(&self, prefix: &str) -> DbResult<Vec<String>> {
        list_sync(prefix)
    }

    async fn delete(&self, key: &str) -> DbResult<()> {
        delete_sync(key)
    }

    fn kind(&self) -> &'static str {
        "opfs"
    }
}
