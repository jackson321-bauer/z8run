//! Cross-Ziel-Vorbereitung fuer `--target native`: Windows/macOS werden
//! als build-bar Spalten geprueft (rustc --emit=metadata, kein Linker).

use serde_json::json;
use std::process::Command;

const TARGETS: [&str; 2] = ["x86_64-pc-windows-gnu", "x86_64-apple-darwin"];

pub fn columns() -> serde_json::Value {
    let probe = std::env::temp_dir().join("z8-cross-probe.rs");
    let _ = std::fs::write(&probe, "pub fn probe() -> u32 { 42 }\n");
    let mut out = Vec::new();
    for t in TARGETS {
        let rustc = rustc_bin();
        let r = Command::new(&rustc)
            .args([
                "--target",
                t,
                "--crate-type",
                "lib",
                "--emit=metadata",
                "-o",
                &format!("/tmp/z8-cross-{t}.rmeta"),
            ])
            .arg(&probe)
            .output();
        let (build_bar, detail) = match r {
            Ok(o) if o.status.success() => (true, "rustc metadata ok".to_string()),
            Ok(o) => (
                false,
                String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("").to_string(),
            ),
            Err(e) => (false, e.to_string()),
        };
        out.push(json!({
            "triple": t,
            "build_bar": build_bar,
            "detail": detail,
        }));
    }
    let _ = std::fs::remove_file(&probe);
    json!(out)
}

fn rustc_bin() -> String {
    let p = std::path::Path::new("/root/.cargo/bin/rustc");
    if p.is_file() {
        return p.display().to_string();
    }
    "rustc".to_string()
}
