//! S3/Restart: Engine-Neustart MIT lokalem Stand -> Blob-Meta sofort da,
//! Blob-Inhalt erst beim ersten get vom Backend (0 Blob-Downloads beim Start).

mod common;

use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use z8run_core::dbnode::types::DbResult;
use z8run_core::dbnode::{DbNode, DummyBackend, StorageBackend};

struct CountingBackend {
    inner: Arc<dyn StorageBackend>,
    blobs_gelesen: AtomicUsize,
}

impl CountingBackend {
    fn neu(inner: Arc<dyn StorageBackend>) -> Self {
        Self { inner, blobs_gelesen: AtomicUsize::new(0) }
    }
    fn blob_reads(&self) -> usize {
        self.blobs_gelesen.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl StorageBackend for CountingBackend {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>> {
        if key.starts_with("blobs/") {
            self.blobs_gelesen.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.read(key).await
    }
    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()> {
        self.inner.write(key, data).await
    }
    async fn list(&self, prefix: &str) -> DbResult<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn delete(&self, key: &str) -> DbResult<()> {
        self.inner.delete(key).await
    }
    fn kind(&self) -> &'static str {
        "counting"
    }
}

#[tokio::test]
async fn restart_laedt_blob_inhalt_erst_beim_get() {
    let base = temp_base("blob-restart");
    let dummy: Arc<dyn StorageBackend> = Arc::new(DummyBackend::new());
    let counting = Arc::new(CountingBackend::neu(dummy));
    let cluster = cluster("c1", &base);
    let inhalt = vec![0x7Eu8; 3 * 1024 * 1024 + 17];

    let node1 = DbNode::new(z8run_core::dbnode::types::DbNodeConfig::default());
    node1
        .open_db_with_storage("db-r", &master(), cluster.clone(), counting.clone())
        .await
        .unwrap();
    node1.reserve("db-r", "s").unwrap();
    let m = node1
        .blob_put_bytes("db-r", "s", "o", "r.bin", "application/octet-stream", &inhalt)
        .await
        .unwrap();
    assert_eq!(counting.blob_reads(), 0, "put darf nichts lesen");
    drop(node1);

    // Neustart: neue Engine, gleicher lokaler Stand + gleiches Backend.
    let node2 = DbNode::new(z8run_core::dbnode::types::DbNodeConfig::default());
    node2
        .open_db_with_storage("db-r", &master(), cluster.clone(), counting.clone())
        .await
        .unwrap();
    let liste = node2.blob_list("db-r").unwrap();
    assert_eq!(liste.len(), 1, "Blob-Meta nach Restart fehlt");
    assert_eq!(liste[0].blob_id, m.blob_id);
    assert_eq!(
        counting.blob_reads(),
        0,
        "Start hat Blob-Inhalt geladen ({} Reads)",
        counting.blob_reads()
    );

    let out = node2.blob_get_bytes("db-r", &m.blob_id).await.unwrap();
    assert_eq!(out, inhalt);
    assert!(counting.blob_reads() > 0, "get hat Backend nicht gelesen");
    println!("BLOB_READS_NACH_GET={}", counting.blob_reads());
}
