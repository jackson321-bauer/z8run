//! Öffentliche Typen des DB-NODE (Engine-Bibliothek, kein z8-Code); serde-fähig.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Fehler mit stabilem Code (Message-Interface + Node-Error-Port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbError {
    pub code: String,
    pub message: String,
}

impl DbError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DbError {}
impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::new("SQLITE", e.to_string())
    }
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        DbError::new("JSON", e.to_string())
    }
}
pub type DbResult<T> = Result<T, DbError>;
/// Globale Engine-Konfiguration.
#[derive(Debug, Clone)]
pub struct DbNodeConfig {
    /// RAM-Budget je offener DB (nur Buchführung; Offload bleibt flach).
    pub ram_budget_per_db: usize,
    /// Nach so vielen WAL-Objekten wird ein Snapshot gezogen (Plan: 64).
    pub wal_snapshot_limit: u64,
    /// Zusätzlich zeitgetrieben (Plan: 1h).
    pub snapshot_interval: Duration,
    /// Timeout für die interne Schreib-Warteschlange je DB (fail-fast).
    pub write_timeout: Duration,
    /// Timeout je Storage-Hop.
    pub storage_timeout: Duration,
}

impl Default for DbNodeConfig {
    fn default() -> Self {
        Self {
            ram_budget_per_db: 5 * 1024 * 1024,
            wal_snapshot_limit: 64,
            snapshot_interval: Duration::from_secs(3600),
            write_timeout: Duration::from_secs(5),
            storage_timeout: Duration::from_secs(10),
        }
    }
}

/// Ziel-Speicher eines Clusters (Adapter je Target, FEST 6).
#[derive(Clone, Serialize, Deserialize)]
pub enum Adapter {
    /// Lokales Dateisystem (Linux/macOS/Windows).
    Fs { root: String },
    /// S3-kompatibel über kv-store (path-dep, kein Provider-SDK).
    S3 {
        host: String,
        region: String,
        access_key: String,
        secret_key: String,
        bucket: String,
        prefix: String,
    },
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Adapter::Fs { root } => f.debug_struct("Fs").field("root", root).finish(),
            Adapter::S3 {
                host,
                region,
                bucket,
                prefix,
                ..
            } => f
                .debug_struct("S3")
                .field("host", host)
                .field("region", region)
                .field("bucket", bucket)
                .field("prefix", prefix)
                .field("secret_key", &"<redacted>")
                .finish(),
        }
    }
}

impl Adapter {
    pub fn kind(&self) -> &'static str {
        match self {
            Adapter::Fs { .. } => "fs",
            Adapter::S3 { .. } => "s3",
        }
    }
}

/// Ein Cluster: lokaler Arbeitsordner + Storage-Adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub cluster_id: String,
    pub local_dir: PathBuf,
    pub adapter: Adapter,
}

/// Reservierungszustand (Ein-Schreiber, FEST 4+5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReservationState {
    #[default]
    Frei,
    Reserviert,
    Schreibend,
}

impl ReservationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReservationState::Frei => "frei",
            ReservationState::Reserviert => "reserviert",
            ReservationState::Schreibend => "schreibend",
        }
    }
}

/// Status einer DB für Canvas-/Proxy-Anzeige.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStatus {
    pub db_id: String,
    pub cluster_id: String,
    pub adapter: String,
    pub local_path: String,
    pub reservation: String,
    pub reserved_by: Option<String>,
    /// Zuletzt angewandte WAL-Nummer (Zeilen-Epoche).
    pub wal_stand: u64,
    /// Zuletzt in den Storage hochgeladene WAL-Nummer.
    pub wal_synced: u64,
    /// Lokal vorhandene, noch nicht hochgeladene WALs.
    pub wal_pending: u64,
    pub snapshots: u64,
    pub remote_wal_downloaded: u64,
    pub restored_from_snapshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteOutcome {
    pub rows_affected: u64,
    pub wal_nr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOutcome {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub rows_affected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalProgress {
    pub db_id: String,
    pub wal_stand: u64,
    pub wal_synced: u64,
    pub wal_pending: u64,
    pub remote_wal_downloaded: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSchema {
    pub name: String,
    pub typ: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub name: String,
    pub columns: Vec<ColumnSchema>,
    pub rows: u64,
    pub wal_stand: u64,
    pub reserved_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaInfo {
    pub db_id: String,
    pub tables: Vec<TableSchema>,
}
