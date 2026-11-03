//! DB-Erstellung für die Setup-API: Z8FC1-File-Cipher + WAL + FTS5 + vec0.
//!
//! Bewiesen kombinierbar (vecprobe 29.10.); hier dieselbe Kombination in
//! einem Node-Helfer. RAM-Offload über PRAGMAs (cache_size, mmap_size).

use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::Connection;
use std::path::Path;

use super::setup_crypto as sc;

pub struct DbDatei {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub vec0: bool,
}

async fn oeffne(
    path: &str,
    key_hex: &str,
    vec0_path: &str,
) -> Result<(SqliteConnection, bool), String> {
    if key_hex.len() != 64 || !key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("db key muss 64 Hex-Zeichen haben".into());
    }
    let raw_key = hex::decode(key_hex).map_err(|e| format!("db key hex: {e}"))?;
    crate::dbnode::cipher_vfs::install();
    crate::dbnode::cipher_vfs::register_key(Path::new(path), &raw_key);
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .vfs("z8cipher")
        .create_if_missing(true);
    // vec0 ist EINGEBRANNT (build.rs) — kein dlopen/kein .so noetig.
    crate::dbnode::vec::register_auto_extension();
    let vec_versucht = !vec0_path.is_empty();
    let mut conn = SqliteConnection::connect_with(&opts)
        .await
        .map_err(|e| format!("DB open {path}: {e}"))?;
    sqlx::query(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -65536;
         PRAGMA mmap_size = 268435456;
         PRAGMA foreign_keys = ON;",
    )
    .execute(&mut conn)
    .await
    .map_err(|e| format!("DB pragmas: {e}"))?;
    // Leseprobe: falscher Key oder beschädigte Datei scheitert hier.
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM sqlite_master")
        .fetch_one(&mut conn)
        .await
        .map_err(|e| format!("DB key check: {e}"))?;
    Ok((conn, vec_versucht))
}

pub async fn erzeugen(
    dir: &str,
    stem: &str,
    key_hex: &str,
    vec0_path: &str,
    space: &str,
    user: &str,
) -> Result<DbDatei, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("DB dir {dir}: {e}"))?;
    let path = format!("{}/{}", dir.trim_end_matches('/'), if stem.ends_with(".db") {
        stem.to_string()
    } else {
        format!("{stem}.db")
    });
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
    let (mut conn, _) = oeffne(&path, key_hex, vec0_path).await?;

    let schema: &[&str] = if stem.contains("config") {
        &[
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('format', 'z8setup/1');",
        ]
    } else {
        &[
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('format', 'z8setup/1');",
            "CREATE TABLE IF NOT EXISTS demo (id INTEGER PRIMARY KEY, note TEXT NOT NULL);",
            "INSERT OR IGNORE INTO demo (id, note) VALUES (1, 'z8run setup demo');",
            "CREATE VIRTUAL TABLE IF NOT EXISTS demo_fts USING fts5(note);",
            "INSERT INTO demo_fts (note) SELECT note FROM demo WHERE id = 1;",
        ]
    };
    for stmt in schema {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .map_err(|e| format!("DB schema {stem}: {e}"))?;
    }

    let mut vec0 = false;
    if !vec0_path.is_empty() {
        let vec_sql = if stem.contains("config") {
            "CREATE VIRTUAL TABLE IF NOT EXISTS config_vec USING vec0(embedding float[4]);"
        } else {
            "CREATE VIRTUAL TABLE IF NOT EXISTS demo_vec USING vec0(embedding float[4]);"
        };
        if sqlx::query(vec_sql).execute(&mut conn).await.is_ok() {
            vec0 = true;
        }
    }

    sqlx::query("INSERT OR REPLACE INTO meta (key, value) VALUES ('space', ?1);")
        .bind(space)
        .execute(&mut conn)
        .await
        .ok();
    sqlx::query("INSERT OR REPLACE INTO meta (key, value) VALUES ('user', ?1);")
        .bind(user)
        .execute(&mut conn)
        .await
        .ok();

    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE);")
        .execute(&mut conn)
        .await
        .map_err(|e| format!("DB checkpoint {stem}: {e}"))?;
    conn.close().await.map_err(|e| format!("DB close {stem}: {e}"))?;
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
    let data = std::fs::read(&path).map_err(|e| format!("DB read {path}: {e}"))?;
    Ok(DbDatei {
        name: path,
        sha256: sc::sha_hex(&data),
        bytes: data.len() as u64,
        vec0,
    })
}
