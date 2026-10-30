#![allow(dead_code)]

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
    DbNode::new(DbNodeConfig {
        wal_snapshot_limit: limit,
        ..Default::default()
    })
}

pub fn master() -> Vec<u8> {
    b"z8-dbbox-test-master-0123456789abcdef".to_vec()
}

/// Führt einen reservierten Write aus (Session "s").
pub async fn write(node: &DbNode, db: &str, sql: &str, params: Vec<serde_json::Value>) -> u64 {
    node.write(db, "s", sql, params).await.unwrap().wal_nr
}

/// Aktuelle VmRSS in KiB (Linux).
pub fn rss_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// Sampler-Thread: misst die RSS-Spitze während einer Operation.
pub struct RssSampler {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    peak: std::sync::Arc<std::sync::atomic::AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RssSampler {
    pub fn start() -> Self {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(rss_kb()));
        let (s, p) = (stop.clone(), peak.clone());
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                let now = rss_kb();
                p.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        Self { stop, peak, handle: Some(handle) }
    }

    /// Stoppt den Sampler und liefert die RSS-Spitze in KiB.
    pub fn stop(mut self) -> u64 {
        use std::sync::atomic::Ordering;
        let peak = self.peak.load(Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        peak
    }
}
