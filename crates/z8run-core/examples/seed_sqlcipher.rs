//! Creates a small SQLCipher-encrypted SQLite database for the proxy test.
//!
//! Usage:
//!   cargo run -p z8run-core --example seed_sqlcipher -- /tmp/demo.db /etc/z8run/db.key

use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::Connection;

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: seed_sqlcipher <db-path> <key-file>".to_string());
    }
    let path = &args[1];
    let key_file = &args[2];

    let raw = std::fs::read_to_string(key_file)
        .map_err(|e| format!("key file {key_file}: {e}"))?;
    let key = raw.trim();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("key file must contain exactly 64 hex characters".to_string());
    }

    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let mut conn = SqliteConnection::connect_with(&opts)
        .await
        .map_err(|e| format!("open {path}: {e}"))?;

    sqlx::query(&format!("PRAGMA key = \"x'{key}'\";"))
        .execute(&mut conn)
        .await
        .map_err(|e| format!("apply key: {e}"))?;
    sqlx::query("PRAGMA cipher_memory_security = ON; PRAGMA temp_store = MEMORY;")
        .execute(&mut conn)
        .await
        .map_err(|e| format!("cipher pragmas: {e}"))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )",
    )
    .execute(&mut conn)
    .await
    .map_err(|e| format!("create table: {e}"))?;
    sqlx::query("DELETE FROM notes")
        .execute(&mut conn)
        .await
        .map_err(|e| format!("clear table: {e}"))?;

    for (title, body) in [
        ("Erster Eintrag", "Hallo aus der verschluesselten S3-Datenbank"),
        ("Zweiter Eintrag", "Der Proxy hat die Datei geladen"),
        ("Dritter Eintrag", "SQLite bleibt verschluesselt auf der Platte"),
    ] {
        sqlx::query("INSERT INTO notes (title, body) VALUES (?, ?)")
            .bind(title)
            .bind(body)
            .execute(&mut conn)
            .await
            .map_err(|e| format!("insert: {e}"))?;
    }

    let _ = conn.close().await;
    println!("seeded {} (encrypted)", path);
    Ok(())
}
