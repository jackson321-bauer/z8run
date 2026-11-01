//! DB-Message-Client: EIN Client, EINE Naht. Spricht serialisierte
//! DbNodeCommand/Event ueber UDS mit der z8run-Engine (kein Direktzugriff
//! auf DB-Dateien, keine eigene Engine).

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use proxy_kern::{DbPort, ProxyError};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::db_events::{cluster, event_value};
use z8run_core::dbnode::{DbNodeCommand, DbNodeEvent};

const MAX_LINE: u64 = 32 * 1024 * 1024;

pub struct UdsDbClient {
    path: PathBuf,
    timeout: Duration,
}

impl UdsDbClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            timeout: Duration::from_secs(30),
        }
    }

    async fn command(&self, cmd: DbNodeCommand) -> Result<Vec<DbNodeEvent>, ProxyError> {
        let body = serde_json::to_vec(&cmd)
            .map_err(|e| ProxyError::Db(format!("serialisieren: {e}")))?;
        let path = self.path.clone();
        let timeout = self.timeout;
        let run = async move {
            let stream = z8run_core::udsv3_stream::connect(&path, "dbnode-msg")
                .map_err(|e| ProxyError::Db(format!("UDS {}: {e}", path.display())))?;
            let (read_half, mut write_half) = tokio::io::split(stream);
            write_half
                .write_all(&body)
                .await
                .map_err(|e| ProxyError::Db(format!("schreiben: {e}")))?;
            write_half
                .write_all(b"\n")
                .await
                .map_err(|e| ProxyError::Db(format!("schreiben: {e}")))?;
            let mut reader = BufReader::new(read_half).take(MAX_LINE);
            let mut line = Vec::new();
            let n = reader
                .read_until(b'\n', &mut line)
                .await
                .map_err(|e| ProxyError::Db(format!("lesen: {e}")))?;
            if n == 0 {
                return Err(ProxyError::Db("Engine hat Verbindung geschlossen".into()));
            }
            serde_json::from_slice::<Vec<DbNodeEvent>>(&line)
                .map_err(|e| ProxyError::Db(format!("Antwort parsen: {e}")))
        };
        tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| ProxyError::Db("DB-Kanal Timeout".into()))?
    }

    pub(crate) async fn one(&self, cmd: DbNodeCommand) -> Result<Value, ProxyError> {
        let events = self.command(cmd).await?;
        let mut last: Option<Value> = None;
        for ev in events {
            last = Some(event_value(ev)?);
        }
        last.ok_or_else(|| ProxyError::Db("Engine lieferte kein Event".into()))
    }
}

#[async_trait]
impl DbPort for UdsDbClient {
    async fn open_db(
        &self,
        db_id: &str,
        master_key_b64: &str,
        cluster_cfg: Value,
    ) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::OpenDb {
            db_id: db_id.to_string(),
            master_key_b64: master_key_b64.to_string(),
            cluster: cluster(cluster_cfg)?,
        })
        .await
    }

    async fn close_db(&self, db_id: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::CloseDb {
            db_id: db_id.to_string(),
        })
        .await
    }

    async fn reserve(&self, db_id: &str, session_id: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::Reserve {
            db_id: db_id.to_string(),
            session_id: session_id.to_string(),
        })
        .await
    }

    async fn release(&self, db_id: &str, session_id: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::Release {
            db_id: db_id.to_string(),
            session_id: session_id.to_string(),
        })
        .await
    }

    async fn query(
        &self,
        db_id: &str,
        sql: &str,
        params: Vec<Value>,
        readonly: bool,
    ) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::Query {
            db_id: db_id.to_string(),
            sql: sql.to_string(),
            params,
            readonly,
        })
        .await
    }

    async fn write(
        &self,
        db_id: &str,
        session_id: &str,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::Write {
            db_id: db_id.to_string(),
            session_id: session_id.to_string(),
            sql: sql.to_string(),
            params,
        })
        .await
    }

    async fn status(&self, db_id: Option<&str>) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::Status {
            db_id: db_id.map(|s| s.to_string()),
        })
        .await
    }

    async fn schema(&self, db_id: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::Schema {
            db_id: db_id.to_string(),
        })
        .await
    }


    async fn blob_session_begin(&self, db_id: &str, session_id: &str, owner: &str, mime: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::BlobSessionBegin { db_id: db_id.into(), session_id: session_id.into(), owner: owner.into(), mime: mime.into() }).await
    }
    async fn blob_session_append(&self, db_id: &str, session_id: &str, sid: &str, data: &[u8], dauer_ms: u64) -> Result<Value, ProxyError> {
        use base64::Engine as _;
        self.one(DbNodeCommand::BlobSessionAppend { db_id: db_id.into(), session_id: session_id.into(), sid: sid.into(), data_b64: base64::engine::general_purpose::STANDARD.encode(data), dauer_ms }).await
    }
    async fn blob_session_finish(&self, db_id: &str, session_id: &str, sid: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::BlobSessionFinish { db_id: db_id.into(), session_id: session_id.into(), sid: sid.into() }).await
    }
    async fn blob_session_get(&self, db_id: &str, session_id: &str, sid: &str) -> Result<Vec<u8>, ProxyError> {
        let v = self.one(DbNodeCommand::BlobSessionGet { db_id: db_id.into(), session_id: session_id.into(), sid: sid.into() }).await?;
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(v.get("bytes_b64").and_then(Value::as_str).unwrap_or("")).map_err(|e| ProxyError::Db(format!("blob_session_get: {e}")))
    }
    async fn blob_session_list(&self, db_id: &str) -> Result<Value, ProxyError> {
        self.one(DbNodeCommand::BlobSessionList { db_id: db_id.into() }).await
    }
}
