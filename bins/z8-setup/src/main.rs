//! z8-setup — die Setup-ENGINE (standalone, keine z8-Flow-Abhaengigkeit).
//! Ruft `z8run_core::...::setup_kern` — DASSELBE Modul wie die Flow-Nodes.

mod health;
mod init;
mod probe;

use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Welt komplett neu bauen (Setup-Keys, Userspaces, Registry, Quorum-Write)
    Init(init::Init),
    /// Provider-Erreichbarkeit + Bucket-Status pruefen
    Health(health::Health),
    /// Ein Objekt per Quorum schreiben (Torture-/Heilungsbeweis)
    Put(probe::Put),
    /// Byte-Gleichheit eines Keys ueber ALLE Provider zeigen
    Replicas(probe::Replicas),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Init(a) => init::run(a).await,
        Cmd::Health(h) => health::run(h).await,
        Cmd::Put(p) => probe::put(p).await,
        Cmd::Replicas(r) => probe::replicas(r).await,
    };
    if let Err(e) = r {
        eprintln!("Z8-SETUP FEHLER: {e}");
        std::process::exit(1);
    }
}
