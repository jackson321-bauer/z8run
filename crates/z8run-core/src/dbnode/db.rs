//! Schreiben (Reservierungspflicht + Warteschlange), Lesen (parallel),
//! WAL-Sync. Der DbNode serialisiert Schreiber JE DB selbst (FEST 5).

use crate::dbnode::crypto;
use crate::dbnode::handle::{open_readonly, DbHandle};
use crate::dbnode::linefs_rows::Aktion;
use crate::dbnode::restore::take_snapshot;
use crate::dbnode::types::{DbError, DbResult, QueryOutcome, WalProgress, WriteOutcome};
use crate::dbnode::wal::{self, WalInner, WalObject};
use base64::Engine;
use serde_json::Value;

impl DbHandle {
    /// Schreiben nur mit gültiger Reservierung dieser Session.
    pub async fn write(&self, session: &str, sql: &str, params: Vec<Value>) -> DbResult<WriteOutcome> {
        wal::validate_sql(sql)?;
        self.begin_write(session)?;
        let inner = WalInner {
            art: "sql".into(),
            sql: sql.to_string(),
            params,
            ops: Vec::new(),
            ts: chrono::Utc::now().to_rfc3339(),
        };
        let result = self.write_inner(inner).await;
        self.end_write();
        result
    }

    /// Zeilen-/Ordner-Commit: EINE WAL-Nummer, EINE Transaktion.
    /// Die Aktionen stammen aus der portierten Zeilen-Planung.
    pub async fn write_ops(&self, session: &str, ops: Vec<Aktion>) -> DbResult<WriteOutcome> {
        self.begin_write(session)?;
        if ops.is_empty() {
            self.end_write();
            return Ok(WriteOutcome {
                rows_affected: 0,
                wal_nr: self.status().wal_stand,
            });
        }
        let inner = WalInner {
            art: "linefs".into(),
            sql: String::new(),
            params: Vec::new(),
            ops,
            ts: chrono::Utc::now().to_rfc3339(),
        };
        let result = self.write_inner(inner).await;
        self.end_write();
        result
    }

    async fn write_inner(&self, inner: WalInner) -> DbResult<WriteOutcome> {
        wal::validate_inner(&inner)?;
        let mut ws = tokio::time::timeout(self.cfg.write_timeout, self.writer.lock())
            .await
            .map_err(|_| DbError::new("TIMEOUT", "Schreib-Warteschlange belegt"))?;

        let nr = ws.state.next_nr.max(1);
        let plain = serde_json::to_vec(&inner)?;
        let sealed = crypto::seal(&self.key, &self.id, nr, &ws.state.prev_hash, &plain)?;
        let seal_b64 = base64::engine::general_purpose::STANDARD.encode(sealed);
        let hash = crypto::wal_hash(nr, &ws.state.prev_hash, &self.id, &seal_b64);
        let obj = WalObject {
            nr,
            prev_hash: ws.state.prev_hash.clone(),
            db: self.id.clone(),
            seal: seal_b64,
            hash: hash.clone(),
        };
        let bytes = serde_json::to_vec(&obj)?;

        // Lokal ausführen, aber erst NACH erfolgreichem SQL hochladen: ein
        // fehlgeschlagenes Statement darf kein Cloud-WAL hinterlassen
        // (sonst blockiert es jeden Reopen). Cloud-Ack vor COMMIT hält die
        // Reihenfolge „Cloud zuerst" für die Dauerhaftigkeit.
        ws.conn.execute_batch("BEGIN IMMEDIATE;")?;
        let apply = wal::apply_inner(&ws.conn, &inner)
            .and_then(|affected| wal::record_epoch(&ws.conn, nr, &hash).map(|_| affected));
        let affected = match apply {
            Ok(a) => a,
            Err(e) => {
                let _ = ws.conn.execute_batch("ROLLBACK;");
                return Err(e);
            }
        };

        let uploaded = matches!(
            tokio::time::timeout(
                self.cfg.storage_timeout,
                self.storage.write(&wal::wal_key(&self.id, nr), &bytes),
            )
            .await,
            Ok(Ok(()))
        );
        if let Err(e) = ws.conn.execute_batch("COMMIT;") {
            let _ = ws.conn.execute_batch("ROLLBACK;");
            return Err(e.into());
        }
        wal::write_local_wal(&self.base_dir, &self.id, nr, &bytes)?;

        ws.state.next_nr = nr + 1;
        ws.state.last_wal = nr;
        ws.state.prev_hash = hash;
        if uploaded && ws.state.synced + 1 == nr {
            ws.state.synced = nr;
        }
        ws.since_snap += 1;
        self.persist(&ws)?;
        let due = ws.since_snap >= self.cfg.wal_snapshot_limit
            || ws.last_snap.elapsed() >= self.cfg.snapshot_interval;
        if due {
            take_snapshot(self, &mut ws).await?;
        }
        self.refresh_stats(&ws);
        Ok(WriteOutcome {
            rows_affected: affected,
            wal_nr: nr,
        })
    }

    /// Paralleles Lesen (MVCC/WAL-Snapshot), keine Reservierung nötig.
    pub fn query(&self, sql: &str, params: &[Value]) -> DbResult<QueryOutcome> {
        let conn = open_readonly(&self.db_path, &self.key)?;
        let (affected, columns, rows) = wal::exec_sql(&conn, sql, params)?;
        Ok(QueryOutcome {
            columns,
            rows,
            rows_affected: affected,
        })
    }

    /// Holt lokal fehlende WAL-Uploads nach (kein Datenverlust bei S3-Ausfall).
    pub async fn wal_sync(&self) -> DbResult<WalProgress> {
        let mut ws = self.writer.lock().await;
        let mut synced = ws.state.synced;
        for nr in (synced + 1)..=ws.state.last_wal {
            let Some(bytes) = wal::read_local_wal(&self.base_dir, &self.id, nr) else {
                break;
            };
            let ok = matches!(
                tokio::time::timeout(
                    self.cfg.storage_timeout,
                    self.storage.write(&wal::wal_key(&self.id, nr), &bytes),
                )
                .await,
                Ok(Ok(()))
            );
            if !ok {
                break;
            }
            synced = nr;
        }
        ws.state.synced = synced;
        self.persist(&ws)?;
        self.refresh_stats(&ws);
        Ok(WalProgress {
            db_id: self.id.clone(),
            wal_stand: ws.state.last_wal,
            wal_synced: synced,
            wal_pending: ws.state.last_wal.saturating_sub(synced),
            remote_wal_downloaded: ws.downloaded,
        })
    }
}
