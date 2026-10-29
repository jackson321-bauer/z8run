//! Baut die sqlite-vec C-Quelle (v0.1.9, SHA256 im S1-Log) in den
//! SQLCipher-Bundled-Build ein. Kein load_extension: die Registrierung
//! passiert per sqlite3_auto_extension (siehe dbnode/vec.rs).

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=vendor/sqlite-vec.c");
    println!("cargo:rerun-if-changed=vendor/sqlite-vec.h");

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "wasm32" {
        return;
    }

    let sqlite_include = std::env::var("DEP_SQLITE3_INCLUDE")
        .ok()
        .map(PathBuf::from)
        .or_else(registry_include)
        .expect("sqlite3.h nicht gefunden (DEP_SQLITE3_INCLUDE fehlt)");

    cc::Build::new()
        .file("vendor/sqlite-vec.c")
        .include("vendor")
        .include(sqlite_include)
        .define("SQLITE_CORE", None)
        .warnings(false)
        .compile("sqlite_vec0");
}

/// Fallback: sqlite3.h aus dem Cargo-Registry-Quellbaum des gebundelten
/// libsqlite3-sys (SQLCipher-Variante).
fn registry_include() -> Option<PathBuf> {
    let home = std::env::var("CARGO_HOME").ok().map(PathBuf::from)?;
    let src = home.join("registry").join("src");
    for entry in std::fs::read_dir(src).ok()? {
        let entry = entry.ok()?;
        for pkg in std::fs::read_dir(entry.path()).ok()? {
            let pkg = pkg.ok()?;
            let name = pkg.file_name();
            if name.to_string_lossy().starts_with("libsqlite3-sys-") {
                let dir = pkg.path().join("sqlcipher");
                if dir.join("sqlite3.h").exists() {
                    return Some(dir);
                }
            }
        }
    }
    None
}
