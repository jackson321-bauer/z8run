//! OPFS-Zugriff ueber SyncAccessHandle (Worker-Pflicht). Die JS-Glue steht
//! inline, damit keine web-sys-Feature-Matrix die API bricht.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = r#"
export async function z8_opfs_write(name, bytes) {
  const dir = await navigator.storage.getDirectory();
  const h = await dir.getFileHandle(name, { create: true });
  // Worker: synchroner Handle (Pflichtpfad). Main-Thread-Test: async Writable.
  if (typeof h.createSyncAccessHandle === "function") {
    const sh = await h.createSyncAccessHandle();
    try { sh.truncate(0); sh.write(bytes, { at: 0 }); sh.flush(); }
    finally { sh.close(); }
  } else {
    const w = await h.createWritable();
    await w.write(bytes);
    await w.close();
  }
  return bytes.length;
}
export async function z8_opfs_read(name) {
  const dir = await navigator.storage.getDirectory();
  try {
    const h = await dir.getFileHandle(name);
    if (typeof h.createSyncAccessHandle === "function") {
      const sh = await h.createSyncAccessHandle();
      try {
        const n = sh.getSize();
        const b = new Uint8Array(n);
        sh.read(b, { at: 0 });
        return b;
      } finally { sh.close(); }
    }
    const f = await h.getFile();
    return new Uint8Array(await f.arrayBuffer());
  } catch (e) { return null; }
}
export async function z8_opfs_list() {
  const dir = await navigator.storage.getDirectory();
  const out = [];
  for await (const [name] of dir.entries()) out.push(name);
  out.sort();
  return out;
}
export async function z8_opfs_delete(name) {
  const dir = await navigator.storage.getDirectory();
  try { await dir.removeEntry(name); return true; } catch (e) { return false; }
}
export async function z8_opfs_persist() {
  return await navigator.storage.persist();
}
export async function z8_opfs_quota() {
  const e = await navigator.storage.estimate();
  return { quota: e.quota, usage: e.usage };
}
export async function z8_fetch(url, method, headers, body) {
  const r = await fetch(url, { method, headers: headers || {}, body: body || undefined });
  const buf = new Uint8Array(await r.arrayBuffer());
  return { status: r.status, bytes: buf };
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = z8_opfs_write)]
    pub fn write(name: &str, bytes: &[u8]) -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_opfs_read)]
    pub fn read(name: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_opfs_list)]
    pub fn list() -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_opfs_delete)]
    pub fn delete(name: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_opfs_persist)]
    pub fn persist() -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_opfs_quota)]
    pub fn quota() -> js_sys::Promise;
    #[wasm_bindgen(js_name = z8_fetch)]
    pub fn fetch(url: &str, method: &str, headers: JsValue, body: JsValue) -> js_sys::Promise;
}

pub async fn write_async(name: &str, bytes: &[u8]) -> Result<usize, String> {
    let v = wasm_bindgen_futures::JsFuture::from(write(name, bytes))
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok(v.as_f64().unwrap_or(0.0) as usize)
}

pub async fn read_async(name: &str) -> Option<Vec<u8>> {
    let v = wasm_bindgen_futures::JsFuture::from(read(name)).await.ok()?;
    if v.is_null() || v.is_undefined() {
        return None;
    }
    js_sys::Uint8Array::new(&v).to_vec().into()
}

pub async fn list_async() -> Vec<String> {
    let Ok(v) = wasm_bindgen_futures::JsFuture::from(list()).await else {
        return Vec::new();
    };
    js_sys::Array::from(&v)
        .iter()
        .map(|x| x.as_string().unwrap_or_default())
        .collect()
}

pub async fn delete_async(name: &str) -> bool {
    wasm_bindgen_futures::JsFuture::from(delete(name))
        .await
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}
