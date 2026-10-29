//! Generates the standalone Cargo project for an exported flow.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use z8run_core::canvas::canvas_to_flow;
use z8run_core::flow::Flow;

use crate::obfuscate::Names;
use crate::secrets;
use crate::templates;
use crate::triggers::TriggerSpec;

/// Export mode baked into the generated runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cli,
    Server,
}

/// What to generate and where.
pub struct Options {
    pub out_dir: PathBuf,
    pub mode: Mode,
    pub readable: bool,
    pub build: bool,
    pub core_path: Option<PathBuf>,
}

/// Result of a successful export.
pub struct Generated {
    pub dir: PathBuf,
    pub binary: Option<PathBuf>,
}

/// Default path-dependency target: the real source tree this tool was built in.
pub fn default_core_path() -> Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = manifest.join("../../crates/z8run-core");
    core.canonicalize()
        .with_context(|| format!("z8run-core source not found at {}", core.display()))
}

fn strip_configs(stored: &Flow) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(stored)?;
    if let Some(nodes) = value
        .get_mut("metadata")
        .and_then(|m| m.get_mut("positions"))
        .and_then(|p| p.get_mut("canvas_nodes"))
        .and_then(|n| n.as_array_mut())
    {
        for node in nodes {
            if let Some(data) = node.get_mut("data").and_then(|d| d.as_object_mut()) {
                data.remove("config");
            }
        }
    }
    Ok(value)
}

fn method_router(method: &str) -> &'static str {
    match method {
        "GET" => "get",
        "POST" => "post",
        "PUT" => "put",
        "DELETE" => "delete",
        "PATCH" => "patch",
        _ => "any",
    }
}

fn write_cargo(
    dir: &Path,
    pkg: &str,
    bin: &str,
    core: &Path,
    server: bool,
    readable: bool,
) -> Result<()> {
    let mut deps = format!(
        "z8run-core = {{ path = {:?} }}\n\
         tokio = {{ version = \"1\", features = [\"full\"] }}\n\
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

/// Generates the project and optionally builds it.
pub fn generate(stored: &Flow, triggers: &[TriggerSpec], opts: &Options) -> Result<Generated> {
    secrets::assert_clean(stored)?;

    let (compiled, id_map) = canvas_to_flow(stored).context("compile canvas")?;
    let core = match &opts.core_path {
        Some(p) => p.canonicalize().context("core path")?,
        None => default_core_path()?,
    };

    let dir = &opts.out_dir;
    std::fs::create_dir_all(dir.join("src")).context("create src")?;
    std::fs::create_dir_all(dir.join("config")).context("create config")?;

    let names = Names::new(opts.readable);
    let mut config_entries = String::new();
    for node in &compiled.nodes {
        let file = format!("{}.json", names.file_base(&node.id.to_string()));
        let cfg = if node.config.is_null() {
            "{}".to_string()
        } else {
            serde_json::to_string_pretty(&node.config)?
        };
        std::fs::write(dir.join("config").join(&file), cfg).context("write node config")?;
        config_entries.push_str(&format!(
            "    (\"{}\", include_str!(\"../config/{}\")),\n",
            node.id, file
        ));
    }

    let flow_json = strip_configs(stored)?;
    std::fs::write(
        dir.join("flow.json"),
        serde_json::to_string_pretty(&flow_json)?,
    )
    .context("write flow.json")?;

    let slug = Names::new(true);
    let bin = slug.ident(&stored.name);
    let pkg = if opts.readable {
        format!("z8_export_{}", slug.ident(&stored.name))
    } else {
        format!("z8_{}", Names::new(false).file_base(&stored.name))
    };

    let main_rs = match opts.mode {
        Mode::Cli => {
            let t = &triggers[0];
            templates::cli_main(&config_entries, &t.canvas_id, &t.method, &t.path)
        }
        Mode::Server => {
            let mut routes = String::new();
            let mut ids = String::new();
            let mut reg = String::new();
            let mut handlers = String::new();
            for (i, t) in triggers.iter().enumerate() {
                routes.push_str(&format!("    (\"{}\", \"{}\"),\n", t.method, t.path));
                ids.push_str(&format!("    \"{}\",\n", t.canvas_id));
                reg.push_str(&format!(
                    "    router = router.route(\"{}\", axum::routing::{}(h{}));\n",
                    t.path,
                    method_router(&t.method),
                    i
                ));
                handlers.push_str(&format!(
                    "async fn h{i}(axum::extract::State(st): axum::extract::State<AppState>, req: axum::extract::Request) -> axum::response::Response {{ handle(st, {i}, req).await }}\n"
                ));
            }
            if triggers.is_empty() {
                bail!("no triggers to serve");
            }
            templates::server_main(&config_entries, &routes, &ids, &reg, &handlers)
        }
    };

    std::fs::write(dir.join("src/main.rs"), main_rs).context("write main.rs")?;

    // The trigger id map is resolved by canvas_to_flow; fail closed if a
    // declared trigger is not part of the compiled canvas.
    for t in triggers {
        if !id_map.contains_key(&t.canvas_id) {
            bail!("trigger '{}' missing from compiled canvas", t.canvas_id);
        }
    }

    write_cargo(
        dir,
        &pkg,
        &bin,
        &core,
        opts.mode == Mode::Server,
        opts.readable,
    )?;

    let binary = if opts.build {
        Some(
            build(dir, &bin, opts.readable)
                .with_context(|| format!("build in {}", dir.display()))?,
        )
    } else {
        None
    };
    Ok(Generated {
        dir: dir.clone(),
        binary,
    })
}

fn build(dir: &Path, bin: &str, readable: bool) -> Result<PathBuf> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(dir).arg("build");
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
    Ok(dir.join("target").join(profile).join(bin))
}
