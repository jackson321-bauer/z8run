//! DB-NODE als eigene Engine-Bibliothek (KEIN z8-Code im Modul).
//!
//! Verwaltet N Datenbanken über M Cluster gleichmäßig: je DB Key-Hülle,
//! Reservierung, WAL-Strom, Schreib-Warteschlange und RAM-Budget getrennt
//! (FEST 13). Storage über einen Adapter-Trait (FS/S3/Dummy, OPFS andockbar).

pub mod conn;
pub mod crypto;
pub mod db;
mod dispatch;
pub mod handle;
pub mod msg;
pub mod restore;
pub mod schema;
pub mod storage;
pub mod storage_s3;
pub mod types;
pub mod vec;
pub mod wal;

pub use handle::{DbHandle, WriterState};
pub use msg::{serve, DbNodeCommand, DbNodeEvent};
pub use storage::StorageBackend;
pub use storage_s3::{DummyBackend, S3Backend};
pub use types::*;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct DbNode {
    pub config: DbNodeConfig,
    dbs: Mutex<HashMap<String, Arc<DbHandle>>>,
}

impl DbNode {
    pub fn new(config: DbNodeConfig) -> Self {
        Self {
            config,
            dbs: Mutex::new(HashMap::new()),
        }
    }

    pub async fn open_db(
        &self,
        db_id: &str,
        master_key: &[u8],
        cluster: ClusterConfig,
    ) -> DbResult<DbStatus> {
        let storage = self.storage_for(&cluster);
        self.open_db_inner(db_id, master_key, cluster, storage).await
    }

    /// Test-/Naht-Variante mit injiziertem Storage (z. B. DummyBackend).
    pub async fn open_db_with_storage(
        &self,
        db_id: &str,
        master_key: &[u8],
        cluster: ClusterConfig,
        storage: Arc<dyn StorageBackend>,
    ) -> DbResult<DbStatus> {
        self.open_db_inner(db_id, master_key, cluster, storage).await
    }

    fn storage_for(&self, cluster: &ClusterConfig) -> Arc<dyn StorageBackend> {
        match &cluster.adapter {
            Adapter::Fs { root } => Arc::new(storage::FsBackend::new(root)),
            Adapter::S3 {
                host,
                region,
                access_key,
                secret_key,
                bucket,
                prefix,
            } => Arc::new(S3Backend::new(
                kv_store::s3::S3Endpoint {
                    host: host.clone(),
                    region: region.clone(),
                    access_key: access_key.clone(),
                    secret_key: secret_key.clone(),
                },
                bucket.clone(),
                prefix.clone(),
            )),
        }
    }

    async fn open_db_inner(
        &self,
        db_id: &str,
        master_key: &[u8],
        cluster: ClusterConfig,
        storage: Arc<dyn StorageBackend>,
    ) -> DbResult<DbStatus> {
        if let Ok(h) = self.get(db_id) {
            return Ok(h.status());
        }
        let h = Arc::new(DbHandle::assemble_with_storage(
            db_id,
            &cluster,
            self.config.clone(),
            master_key,
            storage,
        )?);
        let ws = restore::open_handle(&h).await?;
        vec::verify(&ws.conn)?;
        *h.writer.lock().await = ws;
        let status = h.status();
        self.dbs.lock().unwrap().insert(db_id.to_string(), h);
        Ok(status)
    }

    pub fn close_db(&self, db_id: &str) -> DbResult<()> {
        let removed = self.dbs.lock().unwrap().remove(db_id);
        if removed.is_none() {
            return Err(DbError::new("NOT_OPEN", format!("DB {db_id} ist nicht offen")));
        }
        Ok(())
    }

    pub fn reserve(&self, db_id: &str, session: &str) -> DbResult<()> {
        self.get(db_id)?.reserve(session)
    }

    pub fn release(&self, db_id: &str, session: &str) -> DbResult<()> {
        self.get(db_id)?.release(session)
    }

    pub async fn write(
        &self,
        db_id: &str,
        session: &str,
        sql: &str,
        params: Vec<serde_json::Value>,
    ) -> DbResult<WriteOutcome> {
        let h = self.get(db_id)?;
        h.write(session, sql, params).await
    }

    pub fn query(
        &self,
        db_id: &str,
        sql: &str,
        params: &[serde_json::Value],
    ) -> DbResult<QueryOutcome> {
        self.get(db_id)?.query(sql, params)
    }

    pub async fn wal_sync(&self, db_id: &str) -> DbResult<WalProgress> {
        self.get(db_id)?.wal_sync().await
    }

    pub fn schema(&self, db_id: &str) -> DbResult<SchemaInfo> {
        self.get(db_id)?.schema()
    }

    pub fn status(&self, db_id: Option<&str>) -> DbResult<Vec<DbStatus>> {
        let guard = self.dbs.lock().unwrap();
        if let Some(id) = db_id {
            return Ok(vec![guard
                .get(id)
                .ok_or_else(|| DbError::new("NOT_OPEN", format!("DB {id} ist nicht offen")))?
                .status()]);
        }
        let mut v: Vec<DbStatus> = guard.values().map(|h| h.status()).collect();
        v.sort_by(|a, b| a.db_id.cmp(&b.db_id));
        Ok(v)
    }

    fn get(&self, db_id: &str) -> DbResult<Arc<DbHandle>> {
        self.dbs
            .lock()
            .unwrap()
            .get(db_id)
            .cloned()
            .ok_or_else(|| DbError::new("NOT_OPEN", format!("DB {db_id} ist nicht offen")))
    }
}
