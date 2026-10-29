//! Gemeinsame Test-Helfer (Temp-Verzeichnisse, Cluster, Master).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use z8run_core::dbnode::types::{Adapter, ClusterConfig, DbNodeConfig};
use z8run_core::dbnode::DbNode;

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn temp_base(name: &str) -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("z8-dbbox-{name}-{}-{seq}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn cluster(cluster_id: &str, base: &Path) -> ClusterConfig {
    ClusterConfig {
        cluster_id: cluster_id.to_string(),
        local_dir: base.to_path_buf(),
        adapter: Adapter::Fs {
            root: base.join("storage").to_string_lossy().to_string(),
        },
    }
}

pub fn cluster_mit_storage(cluster_id: &str, base: &Path, storage_root: &Path) -> ClusterConfig {
    ClusterConfig {
        cluster_id: cluster_id.to_string(),
        local_dir: base.to_path_buf(),
        adapter: Adapter::Fs {
            root: storage_root.to_string_lossy().to_string(),
        },
    }
}

pub fn node() -> DbNode {
    DbNode::new(DbNodeConfig::default())
}

pub fn node_mit_limit(limit: u64) -> DbNode {
    let mut cfg = DbNodeConfig::default();
    cfg.wal_snapshot_limit = limit;
    DbNode::new(cfg)
}

pub fn master() -> Vec<u8> {
    b"z8-dbbox-test-master-0123456789abcdef".to_vec()
}

/// Führt einen reservierten Write aus (Session "s").
pub async fn write(node: &DbNode, db: &str, sql: &str, params: Vec<serde_json::Value>) -> u64 {
    node.write(db, "s", sql, params).await.unwrap().wal_nr
}
