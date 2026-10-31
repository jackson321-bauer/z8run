//! Nativ-Adapter: Systemzeit, OS-Zufall, Dateisystem-Bundles.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use proxy_kern::{Clock, ProxyError, Random, StoragePort};

pub mod db;
pub mod login;
pub mod wasm;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }
}

/// Lokales Bundle-Verzeichnis (Filesystem-Adapter des Storage-Ports).
pub struct FsStorage {
    root: PathBuf,
}

impl FsStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, key: &str) -> Result<PathBuf, ProxyError> {
        let p = Path::new(key);
        if p.is_absolute() || key.split('/').any(|s| s == ".." || s.is_empty()) {
            return Err(ProxyError::Bundle(format!("ungueltiger Key: {key}")));
        }
        Ok(self.root.join(p))
    }
}

#[async_trait]
impl StoragePort for FsStorage {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, ProxyError> {
        let p = self.path(key)?;
        match tokio::fs::read(&p).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ProxyError::Bundle(format!("read {key}: {e}"))),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, ProxyError> {
        let root = self.root.clone();
        let prefix = prefix.trim_end_matches('/').to_string();
        let dir = if prefix.is_empty() {
            root.clone()
        } else {
            self.path(&prefix)?
        };
        let mut out = Vec::new();
        let mut stack = vec![dir];
        while let Some(current) = stack.pop() {
            let mut rd = match tokio::fs::read_dir(&current).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(ProxyError::Bundle(format!("list: {e}"))),
            };
            while let Some(entry) = rd
                .next_entry()
                .await
                .map_err(|e| ProxyError::Bundle(format!("list: {e}")))?
            {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        out.sort();
        Ok(out)
    }
}
