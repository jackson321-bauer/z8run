//! S3: DB-Datei auf Platte ist Z8FC1-Chiffre (ohne Masterkey unlesbar),
//! native Form; dieselbe Datei oeffnet ueber den VFS wieder.

mod common;

use common::*;
use serde_json::json;
use z8run_core::dbnode::file_cipher;

#[tokio::test]
async fn db_datei_ist_chiffre_und_key_gebunden() {
    let base = temp_base("cipher");
    let knoten = node();
    knoten.open_db("db-c", &master(), cluster("c1", &base)).await.unwrap();
    knoten.reserve("db-c", "s").unwrap();
    write(&knoten, "db-c", "CREATE TABLE t (x TEXT)", vec![]).await;
    write(
        &knoten,
        "db-c",
        "INSERT INTO t VALUES (?1)",
        vec![json!("geheim-42")],
    )
    .await;
    // Checkpoint + Close schreibt die Chiffre auf Platte.
    knoten.close_db("db-c").unwrap();

    let db_path = base.join("c1").join("db-c").join("db.sqlite");
    let raw = std::fs::read(&db_path).unwrap();
    assert_eq!(&raw[..5], file_cipher::MAGIC, "DB-Datei ist keine Z8FC1-Chiffre");
    assert!(
        !raw.windows(b"SQLite format 3".len()).any(|w| w == b"SQLite format 3"),
        "DB-Datei enthaelt SQLite-Klartext"
    );
    assert!(
        !raw.windows(b"geheim-42".len()).any(|w| w == b"geheim-42"),
        "DB-Datei enthaelt Klartext-Zeile"
    );
    let db_key = {
        // Derselbe Master oeffnet die Huelle; ein fremder Key nicht.
        let hk = z8run_core::dbnode::crypto::KeyEnvelope::derive(&master(), "db-c").unwrap();
        hk.as_bytes().to_vec()
    };
    assert!(file_cipher::open_bytes(&db_key, &raw).is_ok());
    assert!(file_cipher::open_bytes(&[0u8; 32], &raw).is_err());
    println!("CIPHER_FILE_OK path={} bytes={}", db_path.display(), raw.len());

    // Dieselbe Form ueber den VFS wieder lesbar (neue Node-Instanz).
    let node2 = node();
    node2.open_db("db-c", &master(), cluster("c1", &base)).await.unwrap();
    let rows = node2
        .query("db-c", "SELECT x FROM t", &[])
        .unwrap();
    assert!(rows.rows[0][0].as_str().unwrap().contains("geheim-42"));
    println!("CIPHER_VFS_REOPEN_OK");
}
