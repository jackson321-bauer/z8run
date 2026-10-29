//! `z8-export`: turns a z8run flow into a standalone, server-less project.

mod codegen;
mod loader;
mod obfuscate;
mod secrets;
mod templates;
mod templates_cli;
mod templates_server;
mod toolchain;
mod triggers;
mod wasm;

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};
use std::path::PathBuf;
use uuid::Uuid;
use z8run_core::flow::Flow;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Cli,
    Server,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TargetArg {
    Native,
    Wasm,
}

/// Exports a z8run flow as a Cargo project (optionally built).
#[derive(Parser, Debug)]
#[command(name = "z8-export", version, about)]
#[command(group(
    ArgGroup::new("source")
        .required(true)
        .args(["flow_file", "db"])
))]
struct Args {
    /// Flow JSON file (stored flow or API export).
    #[arg(long, conflicts_with = "db")]
    flow_file: Option<PathBuf>,

    /// SQLite database containing the flow.
    #[arg(long, conflicts_with = "flow_file")]
    db: Option<PathBuf>,

    /// Flow id to load from --db.
    #[arg(long, requires = "db")]
    flow_id: Option<Uuid>,

    /// Output directory for the generated project.
    #[arg(long, default_value = "./z8-export-out")]
    out: PathBuf,

    /// Trigger adapter of the generated runner.
    #[arg(long, value_enum, default_value = "cli")]
    mode: ModeArg,

    /// Build target.
    #[arg(long, value_enum, default_value = "native")]
    target: TargetArg,

    /// Compile the generated project right away.
    #[arg(long)]
    build: bool,

    /// Readable names/debug build instead of obfuscated release (debug only).
    #[arg(long)]
    readable: bool,

    /// Path to the z8run-core source tree (defaults to this build's tree).
    #[arg(long)]
    core_path: Option<PathBuf>,
}

async fn load(args: &Args) -> Result<Flow> {
    if let Some(file) = &args.flow_file {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("read flow file {}", file.display()))?;
        return loader::parse_flow_json(&text);
    }
    let db = args.db.as_ref().expect("clap guarantees --db");
    let id = args.flow_id.context("--flow-id is required with --db")?;
    loader::load_from_db(&db.display().to_string(), id).await
}

fn run(args: Args) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let flow = rt.block_on(load(&args))?;
    let triggers = triggers::collect_triggers(&flow)?;

    let opts = codegen::Options {
        out_dir: args.out.clone(),
        mode: match args.mode {
            ModeArg::Cli => codegen::Mode::Cli,
            ModeArg::Server => codegen::Mode::Server,
        },
        target: match args.target {
            TargetArg::Native => codegen::Target::Native,
            TargetArg::Wasm => codegen::Target::Wasm,
        },
        readable: args.readable,
        build: args.build,
        core_path: args.core_path.clone(),
    };
    let generated = codegen::generate(&flow, &triggers, &opts)?;

    let summary = serde_json::json!({
        "flow_id": flow.id,
        "flow_name": flow.name,
        "mode": match args.mode { ModeArg::Cli => "cli", ModeArg::Server => "server" },
        "target": match args.target { TargetArg::Native => "native", TargetArg::Wasm => "wasm" },
        "project": generated.dir,
        "binary": generated.binary,
        "triggers": triggers,
    });
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("z8-export: {e:#}");
        std::process::exit(1);
    }
}
