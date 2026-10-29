//! DB-Endpunktprüfung für setup_verify: SQLCipher öffnen + Tabellen lesen.

use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::Connection;


fn fail(msg: impl Into<String>) -> ! {
    eprintln!("VERIFY ROT: {}", msg.into());
    std::process::exit(1);
}

pub async fn db_pruefen(key_hex: &str, bytes: &[u8], name: &str) {
    let path = std::env::temp_dir().join(format!("z8verify-{name}-{}.db", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let opts = SqliteConnectOptions::new().filename(&path).create_if_missing(false);
    let mut conn = match SqliteConnection::connect_with(&opts).await {
        Ok(c) => c,
        Err(e) => fail(format!("DB open {name}: {e}")),
    };
    if let Err(e) = sqlx::query(&format!("PRAGMA key = \"x'{key_hex}'\";"))
        .execute(&mut conn)
        .await
    {
        fail(format!("DB key {name}: {e}"));
    }
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
    println!("    DB {name}: entschlüsselt, Tabellen={names:?}");
    let _ = conn.close().await;
    let _ = std::fs::remove_file(&path);
}

