//! Generates the standalone Cargo project for an exported flow.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use z8run_core::canvas::canvas_to_flow;
use z8run_core::flow::Flow;

use crate::obfuscate::{FnNames, Names};
use crate::secrets;
use crate::templates;
use crate::toolchain::{build, default_core_path, write_cargo};
use crate::triggers::TriggerSpec;
use crate::wasm::check_wasm_supported;

/// Export mode baked into the generated runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cli,
    Server,
}

/// Build target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Native,
    Wasm,
}

/// What to generate and where.
pub struct Options {
    pub out_dir: PathBuf,
    pub mode: Mode,
    pub target: Target,
    pub readable: bool,
    pub build: bool,
    pub core_path: Option<PathBuf>,
}

/// Result of a successful export.
pub struct Generated {
    pub dir: PathBuf,
    pub binary: Option<PathBuf>,
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
    // The canvas is the only graph source for `canvas_to_flow`. Drop the
    // legacy top-level node list so its configs can never leak into flow.json.
    if let Some(obj) = value.as_object_mut() {
        obj.insert("nodes".into(), serde_json::Value::Array(Vec::new()));
        obj.insert("edges".into(), serde_json::Value::Array(Vec::new()));
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

/// Generates the project and optionally builds it.
pub fn generate(stored: &Flow, triggers: &[TriggerSpec], opts: &Options) -> Result<Generated> {
    secrets::assert_clean(stored)?;
    if opts.target == Target::Wasm {
        if opts.mode != Mode::Cli {
            bail!("target wasm unterstützt nur --mode cli");
        }
        check_wasm_supported(stored)?;
    }

    let (compiled, id_map) = canvas_to_flow(stored).context("compile canvas")?;
    let core = match &opts.core_path {
        Some(p) => p.canonicalize().context("core path")?,
        None => default_core_path()?,
    };

    let dir = &opts.out_dir;
    std::fs::create_dir_all(dir.join("src")).context("create src")?;
    std::fs::create_dir_all(dir.join("config")).context("create config")?;

    let names = Names::new(opts.readable);
    let fns = FnNames::new(&names);
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
            templates::cli_main(
                &config_entries,
                &t.canvas_id,
                &t.method,
                &t.path,
                opts.target == Target::Wasm,
                &fns,
            )
        }
        Mode::Server => {
            let mut routes = String::new();
            let mut ids = String::new();
            let mut reg = String::new();
            let mut handlers = String::new();
            for (i, t) in triggers.iter().enumerate() {
                routes.push_str(&format!("    (\"{}\", \"{}\"),\n", t.method, t.path));
                ids.push_str(&format!("    \"{}\",\n", t.canvas_id));
                let handler = names.ident(&format!("handler{i}"));
                reg.push_str(&format!(
                    "    router = router.route(\"{}\", axum::routing::{}({}));\n",
                    t.path,
                    method_router(&t.method),
                    handler
                ));
                handlers.push_str(&format!(
                    "async fn {handler}(axum::extract::State(st): axum::extract::State<AppState>, req: axum::extract::Request) -> axum::response::Response {{ __FN_HANDLE__(st, {i}, req).await }}\n"
                ));
            }
            if triggers.is_empty() {
                bail!("no triggers to serve");
            }
            templates::server_main(&config_entries, &routes, &ids, &reg, &handlers, &fns)
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
        opts.target == Target::Wasm,
    )?;

    let binary = if opts.build {
        Some(
            build(dir, &bin, opts.readable, opts.target == Target::Wasm)
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
