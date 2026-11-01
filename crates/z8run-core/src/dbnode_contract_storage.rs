//! Nativ-/Browser-gemeinsame Storage-Naht des DB-NODE (EIN Trait, zwei
//! Implementierungen: FsBackend nativ, OpfsBackend im Browser-Worker).
//! Der Trait selbst macht kein I/O und ist target-neutral.

use crate::dbnode_contract_types::{DbError, DbResult};
use async_trait::async_trait;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>>;
    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()>;
    async fn list(&self, prefix: &str) -> DbResult<Vec<String>>;
    async fn delete(&self, key: &str) -> DbResult<()>;
    fn kind(&self) -> &'static str;
}

/// Target-neutraler Key-Schutz (kein `std::path`, damit OPFS/S3 ihn teilen).
pub fn valid_key(key: &str) -> DbResult<()> {
    if key.is_empty() || key.starts_with('/') || key.split('/').any(|s| s == ".." || s.is_empty()) {
        return Err(DbError::new("STORAGE", format!("ungültiger Key: {key}")));
    }
    Ok(())
}
