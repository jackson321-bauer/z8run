//! Restart-Pfad: gültiger lokaler Stand -> nur fehlenden WAL-Schwanz
//! ziehen; ohne lokalen Stand -> Cloud-Snapshot + WALs ab snap+1.
//! Verhalten wie wal_restart_sim.py (Referenz).

use crate::dbnode::crypto;
use crate::dbnode::handle::{
    open_encrypted, prepare_writer, DbHandle, WriterState,
};
use crate::dbnode::types::{DbError, DbResult};
use crate::dbnode::wal::{self, LocalState, WalInner, WalObject};
use base64::Engine;
use serde_json::json;
use std::time::Instant;

pub async fn open_handle(h: &DbHandle) -> DbResult<WriterState> {
    let mut state = if h.db_path.exists() {
        let conn = open_encrypted(&h.db_path, &h.key)?;
        prepare_writer(&conn, h.cfg.ram_budget_per_db)?;
        let st = wal::load_state(&h.base_dir, &h.id)
            .unwrap_or_else(|| derive_state_from_local(h));
        WriterState {
            conn,
            state: st,
            since_snap: 0,
            last_snap: Instant::now(),
            snapshots: 0,
            downloaded: 0,
            restored: false,
        }
    } else {
        let mut st = LocalState::default();
        let mut restored = false;
        if let Some(snap_nr) = neuester_snapshot(h).await? {
            st = restore_snapshot(h, snap_nr).await?;
            restored = true;
        }
        let conn = open_encrypted(&h.db_path, &h.key)?;
        prepare_writer(&conn, h.cfg.ram_budget_per_db)?;
        WriterState {
            conn,
            state: st,
            since_snap: 0,
            last_snap: Instant::now(),
            snapshots: 0,
            downloaded: 0,
            restored,
        }
    };

    state.downloaded = ziehe_fehlende_wals(h, &mut state).await?;
    h.persist(&state)?;
    h.refresh_stats(&state);
    Ok(state)
}

fn derive_state_from_local(h: &DbHandle) -> LocalState {
    let dir = h.base_dir.join(&h.id).join("wal");
    let mut max = 0u64;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if let Some(nr) = wal::nr_aus_key(&e.file_name().to_string_lossy()) {
                max = max.max(nr);
            }
        }
    }
    if max == 0 {
        return LocalState::default();
    }
    let obj = wal::read_local_wal(&h.base_dir, &h.id, max)
        .and_then(|b| serde_json::from_slice::<WalObject>(&b).ok());
    LocalState {
        next_nr: max + 1,
        last_wal: max,
        synced: max,
        prev_hash: obj.map(|o| o.hash).unwrap_or_default(),
        snap_nr: 0,
    }
}

async fn neuester_snapshot(h: &DbHandle) -> DbResult<Option<u64>> {
    let keys = h.storage.list(&format!("snap/{}/", h.id)).await?;
    let max = keys
        .iter()
        .filter(|k| k.ends_with(".meta"))
        .filter_map(|k| wal::nr_aus_key(k))
        .max();
    Ok(max)
}

async fn restore_snapshot(h: &DbHandle, nr: u64) -> DbResult<LocalState> {
    let bytes = h
        .storage
        .read(&wal::snap_key(&h.id, nr))
        .await?
        .ok_or_else(|| DbError::new("RESTORE", "Snapshot-Datei fehlt"))?;
    std::fs::write(&h.db_path, bytes)
        .map_err(|e| DbError::new("RESTORE", format!("Snapshot schreiben: {e}")))?;
    let meta = h
        .storage
        .read(&wal::snap_meta_key(&h.id, nr))
        .await?
        .ok_or_else(|| DbError::new("RESTORE", "Snapshot-Meta fehlt"))?;
    let plain = crypto::open(&h.key, &h.id, nr, "", &meta)?;
    let v: serde_json::Value = serde_json::from_slice(&plain)?;
    let last_wal = v["last_wal"].as_u64().unwrap_or(nr);
    Ok(LocalState {
        next_nr: last_wal + 1,
        last_wal,
        synced: last_wal,
        prev_hash: v["prev_hash"].as_str().unwrap_or_default().to_string(),
        snap_nr: nr,
    })
}

async fn ziehe_fehlende_wals(h: &DbHandle, ws: &mut WriterState) -> DbResult<u64> {
    let keys = h.storage.list(&format!("wal/{}/", h.id)).await?;
    let mut nrs: Vec<u64> = keys.iter().filter_map(|k| wal::nr_aus_key(k)).collect();
    nrs.sort_unstable();
    nrs.dedup();
    let mut downloaded = 0u64;
    let mut erwartet = ws.state.last_wal + 1;
    let letzter_stand = ws.state.last_wal;
    for nr in nrs.into_iter().filter(|n| *n > letzter_stand) {
        if nr != erwartet {
            return Err(DbError::new(
                "WAL_GAP",
                format!("WAL-Lücke: erwartet {erwartet}, gefunden {nr}"),
            ));
        }
        let bytes = h
            .storage
            .read(&wal::wal_key(&h.id, nr))
            .await?
            .ok_or_else(|| DbError::new("WAL", "WAL-Objekt fehlt"))?;
        let obj: WalObject = serde_json::from_slice(&bytes)?;
        wende_wal_an(h, ws, &obj)?;
        ws.state.last_wal = nr;
        ws.state.next_nr = nr + 1;
        ws.state.prev_hash = obj.hash;
        ws.state.synced = nr;
        erwartet = nr + 1;
        downloaded += 1;
    }
    Ok(downloaded)
}

pub fn wende_wal_an(h: &DbHandle, ws: &mut WriterState, obj: &WalObject) -> DbResult<()> {
    if obj.db != h.id {
        return Err(DbError::new("WAL", "WAL gehört anderer DB"));
    }
    let expect = crypto::wal_hash(obj.nr, &obj.prev_hash, &obj.db, &obj.seal);
    if expect != obj.hash {
        return Err(DbError::new("SIGNATUR", "WAL-Kopfhash stimmt nicht"));
    }
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(&obj.seal)
        .map_err(|e| DbError::new("WAL", format!("seal base64: {e}")))?;
    // Idempotenz: Commit und state.json sind nicht atomar. Existiert die
    // Zeilen-Epoche bereits, wurde der WAL schon angewandt -> NICHT erneut
    // ausführen (sonst Doppel-Insert nach Crash zwischen Commit und Persist).
    let schon: i64 = ws.conn.query_row(
        "SELECT count(*) FROM _z8_line_epochs WHERE nr = ?1",
        rusqlite::params![obj.nr as i64],
        |r| r.get(0),
    )?;
    if schon > 0 {
        return Ok(());
    }
    let plain = crypto::open(&h.key, &h.id, obj.nr, &obj.prev_hash, &sealed)?;
    let inner: WalInner = serde_json::from_slice(&plain)?;
    wal::apply_inner(&ws.conn, &inner)?;
    wal::record_epoch(&ws.conn, obj.nr, &obj.hash)?;
    Ok(())
}

/// Snapshot = verschlüsselte DB-Datei (SQLCipher) + Meta mit Kettenstand.
pub async fn take_snapshot(h: &DbHandle, ws: &mut WriterState) -> DbResult<()> {
    if ws.state.last_wal == 0 {
        return Ok(());
    }
    ws.conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let bytes = std::fs::read(&h.db_path)
        .map_err(|e| DbError::new("SNAPSHOT", format!("db lesen: {e}")))?;
    let nr = ws.state.last_wal;
    h.storage.write(&wal::snap_key(&h.id, nr), &bytes).await?;
    let meta = json!({
        "snap_nr": nr,
        "last_wal": nr,
        "prev_hash": ws.state.prev_hash,
    });
    // Meta versiegelt+signiert (AEAD+HMAC) — kein unauthentifizierter
    // Kettenstand aus dem Storage.
    let sealed = crypto::seal(&h.key, &h.id, nr, "", &serde_json::to_vec(&meta)?)?;
    h.storage
        .write(&wal::snap_meta_key(&h.id, nr), &sealed)
        .await?;
    ws.state.snap_nr = nr;
    ws.since_snap = 0;
    ws.last_snap = Instant::now();
    ws.snapshots += 1;
    h.persist(ws)?;
    Ok(())
}
