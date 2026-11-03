//! DB-Endpunktprüfung für setup_verify: Z8FC1-Cipher-VFS öffnen + lesen.

use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::Connection;
use std::path::Path;
use z8run_core::dbnode::{cipher_vfs, vec};

fn fail(msg: impl Into<String>) -> ! {
    eprintln!("VERIFY ROT: {}", msg.into());
    std::process::exit(1);
}

pub async fn db_pruefen(key_hex: &str, bytes: &[u8], name: &str) {
    let path = std::env::temp_dir().join(format!("z8verify-{name}-{}.db", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let raw = hex::decode(key_hex).unwrap_or_else(|e| fail(format!("db key {name}: {e}")));
    cipher_vfs::install();
    cipher_vfs::register_key(&path, &raw);
    vec::register_auto_extension();
    let opts = SqliteConnectOptions::new()
        .filename(&path)
        .vfs("z8cipher")
        .create_if_missing(false);
    let mut conn = match SqliteConnection::connect_with(&opts).await {
        Ok(c) => c,
        Err(e) => fail(format!("DB open {name}: {e}")),
    };
    let tabs: Vec<(String,)> = match sqlx::query_as(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
    )
    .fetch_all(&mut conn)
    .await
    {
        Ok(t) => t,
        Err(e) => fail(format!("DB read {name}: {e} (falscher Key?)")),
    };
    let names: Vec<String> = tabs.into_iter().map(|t| t.0).collect();
    if !names.iter().any(|n| n == "meta") {
        fail(format!("DB {name}: meta-Tabelle fehlt"));
    }
    println!("    DB {name}: entschlüsselt, Tabellen={names:?}");
    let schema: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, COALESCE(sql,'') FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap_or_else(|e| fail(format!("DB {name}: Schema-Dump: {e}")));
    println!("    DB {name}: SCHEMA-DUMP {:?}", schema);
    let dump = schema
        .iter()
        .map(|(n, s)| format!("{n}: {s}"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    if dump.contains("secret") {
        fail(format!("DB {name}: Secret-Feld im Schema gefunden"));
    }
    let _ = conn.close().await;
    let _ = std::fs::remove_file(Path::new(&path));
}
