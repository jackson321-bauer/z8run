//! Toolchain discovery, Cargo manifest writing and builds.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default path-dependency target: the real source tree this tool was built in.
pub fn default_core_path() -> Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = manifest.join("../../crates/z8run-core");
    core.canonicalize()
        .with_context(|| format!("z8run-core source not found at {}", core.display()))
}

pub fn write_cargo(
    dir: &Path,
    pkg: &str,
    bin: &str,
    core: &Path,
    server: bool,
    readable: bool,
    wasm: bool,
) -> Result<()> {
    let tokio_features = if wasm {
        "[\"rt\", \"sync\", \"time\", \"macros\"]"
    } else {
        "[\"full\"]"
    };
    let mut deps = format!(
        "z8run-core = {{ path = {:?} }}\n\
         tokio = {{ version = \"1\", features = {tokio_features} }}\n\
         serde_json = \"1\"\n\
         uuid = {{ version = \"1\", features = [\"v4\", \"v5\", \"v7\", \"serde\"] }}\n",
        core.display().to_string()
    );
    if server {
        deps.push_str("axum = { version = \"0.8\", features = [\"macros\"] }\n");
        deps.push_str("urlencoding = \"2\"\n");
    }
    let profile = if readable {
        String::new()
    } else {
        "\n[profile.release]\nlto = true\ncodegen-units = 1\nstrip = true\npanic = \"abort\"\n"
            .to_string()
    };
    let cargo = format!(
        "[package]\nname = \"{pkg}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [[bin]]\nname = \"{bin}\"\npath = \"src/main.rs\"\n\n\
         [workspace]\n\n[dependencies]\n{deps}{profile}"
    );
    std::fs::write(dir.join("Cargo.toml"), cargo).context("write Cargo.toml")?;
    Ok(())
}

fn cargo_bin() -> String {
    if let Ok(cargo) = std::env::var("CARGO") {
        return cargo;
    }
    // MCP/service processes often run with a minimal PATH.
    let home_cargo = Path::new("/root/.cargo/bin/cargo");
    if home_cargo.is_file() {
        return home_cargo.display().to_string();
    }
    "cargo".to_string()
}

pub fn build(dir: &Path, bin: &str, readable: bool, wasm: bool) -> Result<PathBuf> {
    let mut cmd = Command::new(cargo_bin());
    let path = std::env::var("PATH").unwrap_or_default();
    cmd.env("PATH", format!("/root/.cargo/bin:{path}"));
    cmd.current_dir(dir).arg("build");
    if wasm {
        cmd.args(["--target", "wasm32-wasip1"]);
    }
    if !readable {
        cmd.arg("--release");
    }
    let out = cmd.output().context("run cargo build")?;
    if !out.status.success() {
        bail!(
            "cargo build failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let profile = if readable { "debug" } else { "release" };
    let name = if wasm {
        format!("{bin}.wasm")
    } else {
        bin.to_string()
    };
    let mut out = dir.join("target");
    if wasm {
        out = out.join("wasm32-wasip1");
    }
    Ok(out.join(profile).join(name))
}
