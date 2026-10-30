//! DbHandle je Datenbank: Key-Hülle, Reservierung, Storage, Writer-Zustand.
//! Getrennte Zustände pro DB (FEST 13), kein globaler Modus.

use crate::dbnode::crypto::KeyEnvelope;
use crate::dbnode::storage::{FsBackend, StorageBackend};
use crate::dbnode::storage_s3::S3Backend;
use crate::dbnode::types::*;
use crate::dbnode::wal::{self, LocalState};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use crate::dbnode::conn::{open_encrypted, open_readonly, prepare_writer};

pub struct DbHandle {
    pub id: String,
    pub cluster_id: String,
    pub adapter: String,
    pub base_dir: PathBuf,
    pub db_path: PathBuf,
    pub storage: Arc<dyn StorageBackend>,
    pub key: KeyEnvelope,
    pub writer: tokio::sync::Mutex<WriterState>,
    pub reservation: Mutex<Reservation>,
    pub stats: Mutex<Stats>,
    pub cfg: DbNodeConfig,
}

pub struct WriterState {
    pub conn: Connection,
    pub state: LocalState,
    pub since_snap: u64,
    pub last_snap: Instant,
    pub snapshots: u64,
    pub downloaded: u64,
    pub restored: bool,
}

#[derive(Default)]
pub struct Reservation {
    pub state: ReservationState,
    pub by: Option<String>,
}

#[derive(Default)]
pub struct Stats {
    pub last_wal: u64,
    pub synced: u64,
    pub pending: u64,
    pub snapshots: u64,
    pub downloaded: u64,
    pub restored: bool,
}

fn storage_for(cluster: &ClusterConfig) -> Arc<dyn StorageBackend> {
    match &cluster.adapter {
        Adapter::Fs { root } => Arc::new(FsBackend::new(root)),
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

impl DbHandle {
    pub fn assemble(
        db_id: &str,
        cluster: &ClusterConfig,
        cfg: DbNodeConfig,
        master: &[u8],
    ) -> DbResult<Self> {
        let storage = storage_for(cluster);
        Self::assemble_with_storage(db_id, cluster, cfg, master, storage)
    }

    /// Wie assemble, aber mit injiziertem Adapter (Tests/Nahtbeweis).
    pub fn assemble_with_storage(
        db_id: &str,
        cluster: &ClusterConfig,
        cfg: DbNodeConfig,
        master: &[u8],
        storage: Arc<dyn StorageBackend>,
    ) -> DbResult<Self> {
        let base_dir = cluster.local_dir.join(&cluster.cluster_id);
        let db_path = wal::db_dir(&base_dir, db_id).join("db.sqlite");
        std::fs::create_dir_all(db_path.parent().unwrap_or(&base_dir))
            .map_err(|e| DbError::new("FS", format!("mkdir db: {e}")))?;
        let key = KeyEnvelope::derive(master, db_id)?;
        Ok(Self {
            id: db_id.to_string(),
            cluster_id: cluster.cluster_id.clone(),
            adapter: cluster.adapter.kind().to_string(),
            base_dir,
            db_path,
            storage,
            key,
            writer: tokio::sync::Mutex::new(WriterState {
                conn: Connection::open_in_memory()?,
                state: LocalState::default(),
                since_snap: 0,
                last_snap: Instant::now(),
                snapshots: 0,
                downloaded: 0,
                restored: false,
            }),
            reservation: Mutex::new(Reservation::default()),
            stats: Mutex::new(Stats::default()),
            cfg,
        })
    }

    pub fn reserve(&self, session: &str) -> DbResult<()> {
        let mut r = self.reservation.lock().unwrap();
        if r.state != ReservationState::Frei {
            return Err(DbError::new(
                "BUSY",
                format!("DB {} ist bereits reserviert", self.id),
            ));
        }
        r.state = ReservationState::Reserviert;
        r.by = Some(session.to_string());
        Ok(())
    }

    pub fn release(&self, session: &str) -> DbResult<()> {
        let mut r = self.reservation.lock().unwrap();
        if r.by.as_deref() != Some(session) {
            return Err(DbError::new("NOT_OWNER", "Reservierung gehört anderer Session"));
        }
        r.state = ReservationState::Frei;
        r.by = None;
        Ok(())
    }

    pub fn begin_write(&self, session: &str) -> DbResult<()> {
        let mut r = self.reservation.lock().unwrap();
        if r.by.as_deref() != Some(session) {
            return Err(DbError::new("NOT_RESERVED", "Schreiben ohne Reservierung"));
        }
        r.state = ReservationState::Schreibend;
        Ok(())
    }

    pub fn end_write(&self) {
        let mut r = self.reservation.lock().unwrap();
        if r.state == ReservationState::Schreibend {
            r.state = ReservationState::Reserviert;
        }
    }

    pub fn status(&self) -> DbStatus {
        let s = self.stats.lock().unwrap();
        let r = self.reservation.lock().unwrap();
        DbStatus {
            db_id: self.id.clone(),
            cluster_id: self.cluster_id.clone(),
            adapter: self.adapter.clone(),
            local_path: self.db_path.to_string_lossy().to_string(),
            reservation: r.state.as_str().to_string(),
            reserved_by: r.by.clone(),
            wal_stand: s.last_wal,
            wal_synced: s.synced,
            wal_pending: s.pending,
            snapshots: s.snapshots,
            remote_wal_downloaded: s.downloaded,
            restored_from_snapshot: s.restored,
        }
    }

    pub fn persist(&self, st: &WriterState) -> DbResult<()> {
        wal::persist_state(&self.base_dir, &self.id, &st.state)
    }

    pub fn refresh_stats(&self, st: &WriterState) {
        let mut s = self.stats.lock().unwrap();
        s.last_wal = st.state.last_wal;
        s.synced = st.state.synced;
        s.pending = st.state.next_nr.saturating_sub(1) - st.state.synced;
        s.snapshots = st.snapshots;
        s.downloaded = st.downloaded;
        s.restored = st.restored;
    }
}
