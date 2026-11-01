//! `--target browser`: EIN Werkzeug baut das Worker-Buendel (wasm-bindgen
//! web) aus crates/z8run-browser und legt worker.js + index.html dazu.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Bundle {
    pub dir: PathBuf,
    pub js: PathBuf,
    pub wasm: PathBuf,
    pub worker: PathBuf,
}

pub fn build(out: &Path, core_path: Option<&Path>) -> Result<Bundle> {
    let core = match core_path {
        Some(p) => p.to_path_buf(),
        None => crate::toolchain::default_core_path()?,
    };
    let repo = core
        .parent()
        .and_then(|p| p.parent())
        .context("core_path ohne Repo-Wurzel")?
        .to_path_buf();
    let cargo = crate::toolchain::cargo_bin_pub();
    let path = std::env::var("PATH").unwrap_or_default();
    let status = Command::new(&cargo)
        .env("PATH", format!("/root/.cargo/bin:{path}"))
        .current_dir(&repo)
        .args([
            "build",
            "-p",
            "z8run-browser",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .status()
        .context("cargo build z8run-browser")?;
    if !status.success() {
        bail!("Browser-Kern-Build fehlgeschlagen");
    }
    let wasm_in = repo
        .join("target/wasm32-unknown-unknown/release/z8run_browser.wasm");
    if !wasm_in.exists() {
        bail!("WASM nicht gefunden: {}", wasm_in.display());
    }
    let pkg = out.join("wasm");
    std::fs::create_dir_all(&pkg)?;
    let bindgen = wasm_bindgen_bin();
    let st = Command::new(&bindgen)
        .args(["--target", "web", "--out-dir"])
        .arg(&pkg)
        .arg(&wasm_in)
        .status()
        .with_context(|| format!("wasm-bindgen starten ({bindgen})"))?;
    if !st.success() {
        bail!("wasm-bindgen fehlgeschlagen");
    }
    std::fs::write(out.join("worker.js"), WORKER)?;
    std::fs::write(out.join("index.html"), INDEX)?;
    Ok(Bundle {
        dir: out.to_path_buf(),
        js: pkg.join("z8run_browser.js"),
        wasm: pkg.join("z8run_browser_bg.wasm"),
        worker: out.join("worker.js"),
    })
}

fn wasm_bindgen_bin() -> String {
    let p = Path::new("/root/.cargo/bin/wasm-bindgen");
    if p.is_file() {
        return p.display().to_string();
    }
    "wasm-bindgen".to_string()
}

const WORKER: &str = r#"import init, * as core from './wasm/z8run_browser.js';
await init();
self.onmessage = async (e) => {
  try {
    const req = typeof e.data === 'string' ? e.data : JSON.stringify(e.data);
    self.postMessage(await core.facade(req));
  } catch (err) {
    self.postMessage(JSON.stringify({status: 500, body: {error: String(err)}}));
  }
};
self.postMessage(JSON.stringify({status: 200, body: {ready: true}}));
"#;

const INDEX: &str = r#"<!doctype html><meta charset="utf-8">
<title>z8run Browser-Kern</title>
<div id="out">starte...</div>
<script type="module">
const w = new Worker('./worker.js', { type: 'module' });
let first = true;
w.onmessage = (e) => {
  if (first) { first = false; w.postMessage({ method: 'GET', path: '/v1/status' }); return; }
  document.getElementById('out').textContent = 'FASSADE=' + e.data;
  window.__z8_browser_ok = true;
};
w.onerror = (e) => { document.getElementById('out').textContent = 'WORKER_ERROR=' + e.message; };
w.postMessage({ method: 'GET', path: '/v1/status' });
</script>
"#;
