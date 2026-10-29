//! Storage-Adapter (FEST 6): Trait + FsBackend. S3Backend/DummyBackend
//! liegen in storage_s3.rs, docken aber am selben Trait an (OPFS ebenso).

use crate::dbnode::types::{DbError, DbResult};
use async_trait::async_trait;
use std::path::PathBuf;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>>;
    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()>;
    async fn list(&self, prefix: &str) -> DbResult<Vec<String>>;
    async fn delete(&self, key: &str) -> DbResult<()>;
    fn kind(&self) -> &'static str;
}

fn safe_key(key: &str) -> DbResult<PathBuf> {
    let p = PathBuf::from(key);
    if p.is_absolute() || key.split('/').any(|s| s == ".." || s.is_empty()) {
        return Err(DbError::new("STORAGE", format!("ungültiger Key: {key}")));
    }
    Ok(p)
}

/// Lokales Dateisystem (Linux/macOS/Windows).
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn path(&self, key: &str) -> DbResult<PathBuf> {
        Ok(self.root.join(safe_key(key)?))
    }
}

#[async_trait]
impl StorageBackend for FsBackend {
    async fn read(&self, key: &str) -> DbResult<Option<Vec<u8>>> {
        let p = self.path(key)?;
        match std::fs::read(&p) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(DbError::new("STORAGE", format!("read {}: {e}", p.display()))),
        }
    }

    async fn write(&self, key: &str, data: &[u8]) -> DbResult<()> {
        let p = self.path(key)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| DbError::new("STORAGE", format!("mkdir: {e}")))?;
        }
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, data)
            .map_err(|e| DbError::new("STORAGE", format!("write tmp: {e}")))?;
        std::fs::rename(&tmp, &p)
            .map_err(|e| DbError::new("STORAGE", format!("rename: {e}")))?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> DbResult<Vec<String>> {
        let dir = self.path(prefix.trim_end_matches('/'))?;
        let mut out = Vec::new();
        walk(&dir, &self.root, &mut out)?;
        out.sort();
        Ok(out)
    }

    async fn delete(&self, key: &str) -> DbResult<()> {
        let p = self.path(key)?;
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DbError::new("STORAGE", format!("delete: {e}"))),
        }
    }

    fn kind(&self) -> &'static str {
        "fs"
    }
}

fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) -> DbResult<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(DbError::new("STORAGE", format!("list: {e}"))),
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, root, out)?;
        } else if let Ok(rel) = p.strip_prefix(root) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}
