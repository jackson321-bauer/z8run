//! S3-Beweis: Reader öffnet secret.db AUSSCHLIESSLICH read-only über die
//! bestehende `open_readonly`-Naht, liest je Aufruf frisch und weist
//! Schreibversuche ab. Werte werden nie ausgegeben (nur Name + SHA).
//!
//! Env: SECRET_HASHFILE, SECRET_USER_PW, SECRET_SPACE, SECRET_USER_NAME,
//!      SECRET_OUT (optional), SECRET_EXPECT (optional: sha256 zum Prüfen).

use z8run_core::nodes::setup_nodes::setup_crypto as sc;
use z8run_core::nodes::setup_nodes::setup_secret_cluster as cluster;
use z8run_core::nodes::setup_nodes::setup_secret_db;
use z8run_core::nodes::setup_nodes::setup_secrets as ss;

fn fail(msg: impl Into<String>) -> ! {
    eprintln!("READER ROT: {}", msg.into());
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let pw = std::env::var("SECRET_USER_PW").expect("SECRET_USER_PW");
    let space = std::env::var("SECRET_SPACE").expect("SECRET_SPACE");
    let name = std::env::var("SECRET_USER_NAME").expect("SECRET_USER_NAME");
    let out = std::env::var("SECRET_OUT").unwrap_or_else(|_| "/tmp/z8-secret-reader".into());

    // Adresse = argon2id(name, salt_user(space)) — dieselbe Ableitung wie Setup.
    let salt_space = sc::salt_space(&space);
    let salt_u = sc::salt_user(&salt_space, &name);
    let addr = sc::kette::adresse(&name, &salt_u).unwrap_or_else(|e| fail(format!("adresse: {e}")));

    // Hashdatei: lokal ODER frisch aus S3 (der Eintrag ist die Wahrheit).
    let text = match std::env::var("SECRET_HASHFILE") {
        Ok(p) => std::fs::read_to_string(&p).unwrap_or_else(|e| fail(format!("hashdatei {p}: {e}"))),
        Err(_) => {
            use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;
            let cfg_path = std::env::var("SECRET_S3_CONFIG")
                .unwrap_or_else(|_| "/etc/z8run/kv3-s3.json".into());
            let prefix = std::env::var("SECRET_PREFIX").unwrap_or_default();
            let base = S3Cfg::aus_datei_mit(&cfg_path, None, Some(&prefix))
                .unwrap_or_else(|e| fail(format!("s3 config: {e}")));
            let key = format!("b2b/{addr}.txt");
            let raw = base.get(&key).await.unwrap_or_else(|e| fail(format!("S3 {key}: {e}")));
            String::from_utf8_lossy(&raw).to_string()
        }
    };

    let profil = ss::eintrag_oeffnen_ro(&text, &addr, &pw, &salt_u)
        .unwrap_or_else(|e| fail(format!("ro-Profil: {e}")))
        .unwrap_or_else(|| fail("kein secrets-ro-Eintrag"));
    if !profil.read_only {
        fail("ro-Profil meldet Schreibrecht");
    }
    let cfg = cluster::cfg_aus_profil(&profil).unwrap_or_else(|e| fail(format!("cfg: {e}")));
    let bytes = cluster::lade_db(&cfg)
        .await
        .unwrap_or_else(|e| fail(format!("secret.db S3 get: {e}")));
    std::fs::create_dir_all(&out).unwrap();
    let path = std::path::PathBuf::from(format!("{out}/{}/secret.db", profil.cluster_id));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, &bytes).unwrap();

    let conn = setup_secret_db::oeffne_readonly(&path, &profil.db_key_hex)
        .unwrap_or_else(|e| fail(format!("open_readonly: {e}")));
    let liste = setup_secret_db::liste(&conn).unwrap_or_else(|e| fail(format!("liste: {e}")));
    let ts = chrono::Utc::now().to_rfc3339();
    let sha_db = sc::sha_hex(&bytes);
    println!(
        "READ ts={ts} user={name} addr={addr} cluster={} db_sha256={sha_db} secrets={}",
        profil.cluster_id,
        serde_json::to_string(&liste).unwrap()
    );
    if let Ok(erwartet) = std::env::var("SECRET_EXPECT") {
        let treffer = liste.iter().any(|e| e["sha256"] == serde_json::json!(erwartet));
        if !treffer {
            fail(format!("erwarteter Hash {erwartet} nicht sichtbar"));
        }
        println!("READ_MATCH sha256={erwartet}");
    }

    // NEGATIV: Schreiben muss an query_only/READ_ONLY scheitern.
    match conn.execute(
        "INSERT INTO secrets (ns,name,wert,sha256,version,aktiv,updated_at)
         VALUES ('x','x','x','x',1,1,'x')",
        [],
    ) {
        Ok(n) => fail(format!("read-only-Schreibversuch NICHT abgewiesen (rows={n})")),
        Err(e) => println!("READONLY_WRITE_DENIED err={e}"),
    }
    println!("READER_OK");
}
