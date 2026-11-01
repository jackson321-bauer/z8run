//! S3-Kompatibilitaet: eine im WASM erzeugte Z8FC1-Datei ist nativ lesbar.
//! Der Fixture-Pfad kommt aus Z8_WASM_FIXTURE (vom S3-Lauf erzeugt).

#[test]
fn wasm_datei_ist_nativ_lesbar() {
    let Ok(path) = std::env::var("Z8_WASM_FIXTURE") else {
        eprintln!("SKIP: Z8_WASM_FIXTURE nicht gesetzt");
        return;
    };
    let key = [7u8; 32];
    let sealed = std::fs::read(&path).unwrap();
    assert_eq!(&sealed[..5], z8run_core::dbnode::file_cipher::MAGIC);
    let plain = z8run_core::dbnode::file_cipher::open_bytes(&key, &sealed).unwrap();
    // Nativ denselben VFS oeffnen (Datei liegt als Chiffre auf Platte).
    let dir = std::env::temp_dir().join(format!("z8-wasm-compat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("wasm.db");
    std::fs::write(&db_path, &sealed).unwrap();
    z8run_core::dbnode::cipher_vfs::install();
    z8run_core::dbnode::cipher_vfs::verify_key(&db_path, &key).unwrap();
    z8run_core::dbnode::cipher_vfs::register_key(&db_path, &key);
    let conn = rusqlite::Connection::open_with_flags(
        z8run_core::dbnode::cipher_vfs::uri(&db_path),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let v: String = conn
        .query_row("SELECT x FROM kompat", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "wasm-native-gleich");
    assert!(!plain.is_empty());
    println!("WASM_NATIVE_COMPAT_OK bytes={}", sealed.len());
    let _ = std::fs::remove_dir_all(&dir);
}
