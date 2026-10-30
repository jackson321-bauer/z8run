//! RAM-Beweis: lädt NUR die dbnode-Engine (kein Flow-Engine, kein Server).
//! Misst RSS leer / 1 DB / 5 DBs über /proc/self/status (VmRSS).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use z8run_core::dbnode::types::{Adapter, ClusterConfig, DbNodeConfig};
use z8run_core::dbnode::DbNode;

fn rss_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }
    0
}

fn mb(kb: u64) -> f64 {
    kb as f64 / 1024.0
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn base() -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!(
        "z8-dbbox-ram-{}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::main]
async fn main() {
    let master = b"z8-dbbox-ram-master-0123456789abcdef".to_vec();
    let dir = base();
    let node = DbNode::new(DbNodeConfig::default());
    let rss_leer = rss_kb();
    println!("RSS leer: {:.2} MB", mb(rss_leer));

    let cluster = |id: &str| ClusterConfig {
        cluster_id: id.into(),
        local_dir: dir.clone(),
        adapter: Adapter::Fs {
            root: dir.join("storage").to_string_lossy().to_string(),
        },
    };
    node.open_db("ram-1", &master, cluster("c1")).await.unwrap();
    let rss_1 = rss_kb();
    println!("RSS 1 DB offen: {:.2} MB (+{:.2} MB)", mb(rss_1), mb(rss_1.saturating_sub(rss_leer)));

    for i in 2..=5 {
        node.open_db(&format!("ram-{i}"), &master, cluster("c1"))
            .await
            .unwrap();
    }
    let rss_5 = rss_kb();
    println!("RSS 5 DBs offen: {:.2} MB (+{:.2} MB)", mb(rss_5), mb(rss_5.saturating_sub(rss_leer)));
    let per_db = mb(rss_5.saturating_sub(rss_1)) / 4.0;
    println!("RSS je weitere DB: {:.2} MB", per_db);
    println!(
        "ZIEL Grundlast<10MB: {} | je DB<5MB: {}",
        if mb(rss_leer) < 10.0 { "JA" } else { "NEIN" },
        if per_db < 5.0 { "JA" } else { "NEIN" }
    );
    // Dokumentierter Boden: wer ihn reißt, nennt die Ursache (SQLCipher/OpenSSL).
    println!("BODEN (bundled SQLCipher+OpenSSL) = {:.2} MB", mb(rss_leer));
}
