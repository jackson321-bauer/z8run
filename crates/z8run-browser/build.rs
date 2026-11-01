//! Kompiliert sqlite-vec v0.1.9 fuer wasm32 in den sqlite-wasm-rs-Build
//! (EINGEBRANNT, kein dlopen). Header kommen aus dem sqlite-wasm-rs-Quellbaum.

use std::path::PathBuf;

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch != "wasm32" {
        return;
    }
    println!("cargo:rerun-if-changed=../../crates/z8run-core/vendor/sqlite-vec.c");
    println!("cargo:rerun-if-changed=../../crates/z8run-core/vendor/sqlite-vec.h");
    let root = sqlite_wasm_root().expect("sqlite-wasm-rs Quellbaum nicht gefunden");
    let mut cc = cc::Build::new();
    cc.file("../../crates/z8run-core/vendor/sqlite-vec.c")
        .include("../../crates/z8run-core/vendor")
        .include(root.join("sqlite3"))
        .include(root.join("shim"))
        .include(root.join("shim/musl/arch/generic"))
        .include(root.join("shim/musl/include"))
        .flag("-include")
        .flag(root.join("shim/wasm-shim.h"))
        .flag("-Wno-macro-redefined")
        .define("u_int8_t", "uint8_t")
        .define("u_int16_t", "uint16_t")
        .define("u_int32_t", "uint32_t")
        .define("u_int64_t", "uint64_t")
        .define("SQLITE_CORE", None)
        .warnings(false)
        .compile("sqlite_vec_wasm");
}

fn sqlite_wasm_root() -> Option<PathBuf> {
    let home = std::env::var("CARGO_HOME").ok().map(PathBuf::from)?;
    let src = home.join("registry").join("src");
    for entry in std::fs::read_dir(src).ok()? {
        for pkg in std::fs::read_dir(entry.ok()?.path()).ok()? {
            let pkg = pkg.ok()?;
            if pkg.file_name().to_string_lossy().starts_with("sqlite-wasm-rs-") {
                let dir = pkg.path();
                if dir.join("sqlite3/sqlite3.h").exists() {
                    return Some(dir);
                }
            }
        }
    }
    None
}
