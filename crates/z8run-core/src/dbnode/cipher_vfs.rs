//! Z8CIPHER-VFS: SQLite-Dateien liegen auf Platte ausschliesslich als
//! Z8FC1-Chiffre. SQLite selbst sieht einen normalen Dateibaum (Mem-Spiegel);
//! beim Sync wird der gesamte Satz part-weise verschluesselt geschrieben.
//! Derselbe File-Cipher (file_cipher.rs) laeuft nativ und im Browser.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex, Once, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsqlite_vfs::ffi as sq;
use rsqlite_vfs::{
    register_vfs, MemChunksFile, SQLiteIoMethods, SQLiteVfs, SQLiteVfsFile, VfsAppData,
    VfsError, VfsFile, VfsResult, VfsStore,
};

use crate::dbnode::file_cipher;

pub const VFS_NAME: &str = "z8cipher";
const SQLITE_OK: i32 = 0;

static INSTALL: Once = Once::new();
static TX: OnceLock<mpsc::Sender<(PathBuf, Option<Vec<u8>>, Vec<u8>)>> = OnceLock::new();
static VFS_PTR: OnceLock<usize> = OnceLock::new();
static KEYS: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static ACTIVE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);

fn keys() -> std::sync::MutexGuard<'static, Option<HashMap<String, Vec<u8>>>> {
    KEYS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Meldet den DB-Key fuer einen Dateipfad an (vor dem Oeffnen).
/// Schreibt den aktuellen In-Memory-Stand eines Pfads synchron auf Platte
/// (Snapshot/Checkpoint braucht ihn sofort, nicht erst im Hintergrund).
pub fn persist_path_sync(path: &Path) -> bool {
    let Some(vfs) = VFS_PTR.get().copied().map(|p| p as *mut sq::sqlite3_vfs) else {
        return false;
    };
    let app = unsafe { <EncStore as VfsStore<EncFile, _>>::app_data(vfs) };
    let map = app.lock().unwrap_or_else(|e| e.into_inner());
    match map.get(&path.to_string_lossy().to_string()) {
        Some(f) => f.persist_sync().is_ok(),
        None => false,
    }
}

pub fn register_key(path: &Path, key: &[u8]) {
    let mut k = keys();
    k.get_or_insert_with(HashMap::new)
        .insert(path.to_string_lossy().to_string(), key.to_vec());
}

fn key_for(path: &str) -> Option<Vec<u8>> {
    let k = keys();
    k.as_ref().and_then(|m| m.get(path).cloned())
}

/// Prueft den Key BEVOR er global fuer den Pfad registriert wird.
pub fn verify_key(path: &Path, key: &[u8]) -> Result<(), String> {
    let name = path.to_string_lossy().to_string();
    if let Some(active) = ACTIVE.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        if let Some(v) = active.get(&name) {
            if v.as_slice() != key {
                return Err(format!("{}: falscher Masterkey (offene DB)", path.display()));
            }
            return Ok(());
        }
    }
    if path.exists() {
        let head = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if head.len() >= 5 && &head[..5] == file_cipher::MAGIC {
            file_cipher::open_bytes(key, &head)
                .map_err(|e| format!("{}: falscher Masterkey: {e}", path.display()))?;
        } else if std::env::var("Z8_DB_MIGRATE_OLD").as_deref() != Ok("1") {
            return Err(format!("{}: keine Z8FC1-Chiffre (Alt-Welt)", path.display()));
        }
    }
    Ok(())
}

fn start_persister() {
    let (tx, rx) = mpsc::channel::<(PathBuf, Option<Vec<u8>>, Vec<u8>)>();
    let _ = TX.set(tx);
    std::thread::Builder::new()
        .name("z8cipher-flush".into())
        .spawn(move || {
            let mut batch: HashMap<String, (PathBuf, Option<Vec<u8>>, Vec<u8>)> = HashMap::new();
            loop {
                match rx.recv() {
                    Ok(job) => {
                        batch.insert(job.0.to_string_lossy().to_string(), job);
                        while let Ok(job) = rx.try_recv() {
                            batch.insert(job.0.to_string_lossy().to_string(), job);
                        }
                        for (_, (path, key, plain)) in batch.drain() {
                            if let Some(key) = key {
                                if let Err(e) = file_cipher::write_encrypted(&path, &key, &plain) {
                                    tracing::warn!(error = %e, pfad = %path.display(), "Cipher-Flush fehlgeschlagen");
                                }
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        })
        .ok();
}

pub fn install() {
    INSTALL.call_once(|| {
        if let Ok(vfs) = register_vfs::<EncIo, EncVfs>(VFS_NAME, Mutex::new(HashMap::new()), false) {
            let _ = VFS_PTR.set(vfs as usize);
        }
        start_persister();
    });
}

struct EncFile {
    mem: MemChunksFile,
    path: PathBuf,
    key: Option<Vec<u8>>,
    persist: bool,
}

impl EncFile {
    fn plain_bytes(&self) -> VfsResult<Vec<u8>> {
        let size = self.mem.size()?;
        let mut plain = vec![0u8; size];
        self.mem.read(&mut plain, 0)?;
        Ok(plain)
    }

    /// Sync-Flush enqueued nur (Copy), damit xSync-Latenz klein bleibt;
    /// der Hintergrund-Thread verschluesselt und schreibt (Debounce).
    fn persist(&mut self) -> VfsResult<()> {
        if !self.persist {
            return Ok(());
        }
        let Some(key) = &self.key else { return Ok(()) };
        let plain = self.plain_bytes()?;
        if let Some(tx) = TX.get() {
            let _ = tx.send((self.path.clone(), Some(key.clone()), plain));
        }
        Ok(())
    }

    fn persist_sync(&self) -> VfsResult<()> {
        if !self.persist {
            return Ok(());
        }
        let Some(key) = &self.key else { return Ok(()) };
        let plain = self.plain_bytes()?;
        file_cipher::write_encrypted(&self.path, key, &plain)
            .map_err(|e| VfsError::new(sq::SQLITE_IOERR, format!("cipher: {e}")))
    }
}

impl VfsFile for EncFile {
    fn read(&self, buf: &mut [u8], offset: usize) -> VfsResult<bool> {
        self.mem.read(buf, offset)
    }
    fn write(&mut self, buf: &[u8], offset: usize) -> VfsResult<()> {
        self.mem.write(buf, offset)
    }
    fn truncate(&mut self, size: usize) -> VfsResult<()> {
        self.mem.truncate(size)
    }
    fn flush(&mut self) -> VfsResult<()> {
        self.mem.flush()?;
        self.persist()
    }
    fn size(&self) -> VfsResult<usize> {
        self.mem.size()
    }
}

struct EncStore;

impl VfsStore<EncFile, Mutex<HashMap<String, EncFile>>> for EncStore {
    fn add_file(vfs: *mut sq::sqlite3_vfs, file: &str, flags: i32) -> VfsResult<()> {
        let app = unsafe { Self::app_data(vfs) };
        let mut map = app.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(file) {
            return Ok(());
        }
        let path = PathBuf::from(file);
        let base = file
            .strip_suffix("-wal")
            .or_else(|| file.strip_suffix("-journal"))
            .or_else(|| file.strip_suffix("-shm"))
            .unwrap_or(file);
        let key = key_for(file).or_else(|| key_for(base));
        let is_temp = flags & (sq::SQLITE_OPEN_TEMP_DB | sq::SQLITE_OPEN_TRANSIENT_DB) != 0
            || flags & sq::SQLITE_OPEN_DELETEONCLOSE != 0;
        let mut mem = MemChunksFile::waiting_for_write();
        if let Some(k) = &key {
            if path.exists() {
                match file_cipher::read_encrypted(&path, k) {
                    Ok(Some(plain)) => {
                        mem.write(&plain, 0)?;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // Nur mit explizitem Migrations-Flag wird eine
                        // Alt-Welt (plain/SQLCipher) einmal neu angelegt.
                        if std::env::var("Z8_DB_MIGRATE_OLD").as_deref() == Ok("1") {
                            let bak = path.with_extension(format!(
                                "alt-{}",
                                UNIX_EPOCH.elapsed().map(|d| d.as_secs()).unwrap_or(0)
                            ));
                            let _ = std::fs::rename(&path, &bak);
                            tracing::warn!(
                                meta = true,
                                action = "db_migration_neuangelegt",
                                pfad = %path.display(),
                                backup = %bak.display(),
                                error = %e,
                                "Alt-Welt ist keine Z8FC1-Chiffre; neu angelegt"
                            );
                        } else {
                            return Err(VfsError::new(
                                sq::SQLITE_NOTADB,
                                format!("{}: falscher Key/keine Z8FC1-Chiffre", path.display()),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(k) = &key {
            ACTIVE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert_with(HashMap::new)
                .insert(file.to_string(), k.clone());
        }
        map.insert(
            file.to_string(),
            EncFile {
                mem,
                path,
                key,
                persist: !is_temp && !file.ends_with("-shm"),
            },
        );
        Ok(())
    }

    fn contains_file(vfs: *mut sq::sqlite3_vfs, file: &str) -> VfsResult<bool> {
        let app = unsafe { Self::app_data(vfs) };
        let exists = {
            let map = app.lock().unwrap_or_else(|e| e.into_inner());
            map.contains_key(file)
        };
        if exists {
            return Ok(true);
        }
        if std::path::Path::new(file).exists() {
            // Erstkontakt nach Prozessstart: verschluesselte Datei laden,
            // damit xOpen danach nur noch die Map benutzt.
            Self::add_file(vfs, file, 0)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn delete_file(vfs: *mut sq::sqlite3_vfs, file: &str) -> VfsResult<()> {
        let app = unsafe { Self::app_data(vfs) };
        let mut map = app.lock().unwrap_or_else(|e| e.into_inner());
        // Unlink-Semantik: offene Handles bleiben gueltig, die Datei wird
        // geleert (nicht aus der Map entfernt), Platte wird geloescht.
        if let Some(f) = map.get_mut(file) {
            let _ = f.mem.truncate(0);
            let _ = std::fs::remove_file(&f.path);
        } else {
            let _ = std::fs::remove_file(file);
        }
        Ok(())
    }

    fn with_file<F: Fn(&EncFile) -> VfsResult<i32>>(
        vfs_file: &SQLiteVfsFile,
        f: F,
    ) -> VfsResult<i32> {
        let app = unsafe { Self::app_data(vfs_file.vfs) };
        let map = app.lock().unwrap_or_else(|e| e.into_inner());
        let name = unsafe { vfs_file.name() };
        match map.get(name) {
            Some(file) => f(file),
            None => Err(VfsError::new(sq::SQLITE_IOERR, format!("{name} fehlt"))),
        }
    }

    fn with_file_mut<F: Fn(&mut EncFile) -> VfsResult<i32>>(
        vfs_file: &SQLiteVfsFile,
        f: F,
    ) -> VfsResult<i32> {
        let app = unsafe { Self::app_data(vfs_file.vfs) };
        let mut map = app.lock().unwrap_or_else(|e| e.into_inner());
        let name = unsafe { vfs_file.name() };
        match map.get_mut(name) {
            Some(file) => f(file),
            None => Err(VfsError::new(sq::SQLITE_IOERR, format!("{name} fehlt"))),
        }
    }
}

static SHM: Mutex<Option<HashMap<String, HashMap<usize, Box<[u8]>>>>> = Mutex::new(None);

fn shm_name(p_file: *mut sq::sqlite3_file) -> String {
    unsafe {
        let f = SQLiteVfsFile::from_file(p_file);
        f.name().to_string()
    }
}

unsafe extern "C" fn x_shm_map(
    p_file: *mut sq::sqlite3_file,
    page: i32,
    page_size: i32,
    extend: i32,
    pp: *mut *mut std::ffi::c_void,
) -> i32 {
    if pp.is_null() || page < 0 || page_size <= 0 {
        return sq::SQLITE_IOERR;
    }
    let name = shm_name(p_file);
    let mut guard = SHM.lock().unwrap_or_else(|e| e.into_inner());
    let files = guard.get_or_insert_with(HashMap::new);
    let pages = files.entry(name.clone()).or_insert_with(HashMap::new);
    let idx = page as usize;
    if !pages.contains_key(&idx) {
        if extend == 0 {
            // Seite existiert nicht: SQLite erwartet NULL (kein Fehler).
            *pp = std::ptr::null_mut();
            return SQLITE_OK;
        }
        pages.insert(idx, vec![0u8; page_size as usize].into_boxed_slice());
    }
    *pp = pages
        .get_mut(&idx)
        .expect("gerade angelegt")
        .as_mut_ptr()
        .cast();
    SQLITE_OK
}

unsafe extern "C" fn x_shm_lock(
    _p_file: *mut sq::sqlite3_file,
    _offset: i32,
    _count: i32,
    _flags: i32,
) -> i32 {
    SQLITE_OK
}

unsafe extern "C" fn x_shm_barrier(_p_file: *mut sq::sqlite3_file) {
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

unsafe extern "C" fn x_shm_unmap(_p_file: *mut sq::sqlite3_file, _delete: i32) -> i32 {
    // Seiten NICHT freigeben: andere Verbindungen koennen Zeiger noch halten
    // (WAL-Shm ist prozessweit geteilt). Freigabe erst beim Prozessende.
    SQLITE_OK
}

unsafe extern "C" fn x_close(p_file: *mut sq::sqlite3_file) -> i32 {
    let name = shm_name(p_file);
    let code = <EncIo as SQLiteIoMethods>::xClose(p_file);
    if code == SQLITE_OK {
        // Close macht den Stand synchron dauerhaft (Prozessende/Crash-Fenster).
        let vfs_file = unsafe { SQLiteVfsFile::from_file(p_file) };
        let app = unsafe { <EncStore as VfsStore<EncFile, _>>::app_data(vfs_file.vfs) };
        let map = app.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = map.get(&name) {
            let _ = f.persist_sync();
        }
    }
    code
}

#[derive(Clone, Copy, Default)]
struct EncIo;

impl SQLiteIoMethods for EncIo {
    type File = EncFile;
    type AppData = Mutex<HashMap<String, EncFile>>;
    type Store = EncStore;
    const VERSION: i32 = 2;
    // WAL braucht xShmMap/xShmLock/xShmBarrier/xShmUnmap. Wir liefern einen
    // prozessweiten Shared-Memory-Ersatz (Box-Pointer bleiben stabil).
    const METHODS: sq::sqlite3_io_methods = sq::sqlite3_io_methods {
        iVersion: 2,
        xClose: Some(x_close),
        xRead: Some(<EncIo as SQLiteIoMethods>::xRead),
        xWrite: Some(<EncIo as SQLiteIoMethods>::xWrite),
        xTruncate: Some(<EncIo as SQLiteIoMethods>::xTruncate),
        xSync: Some(<EncIo as SQLiteIoMethods>::xSync),
        xFileSize: Some(<EncIo as SQLiteIoMethods>::xFileSize),
        xLock: Some(<EncIo as SQLiteIoMethods>::xLock),
        xUnlock: Some(<EncIo as SQLiteIoMethods>::xUnlock),
        xCheckReservedLock: Some(<EncIo as SQLiteIoMethods>::xCheckReservedLock),
        xFileControl: Some(<EncIo as SQLiteIoMethods>::xFileControl),
        xSectorSize: Some(<EncIo as SQLiteIoMethods>::xSectorSize),
        xDeviceCharacteristics: Some(<EncIo as SQLiteIoMethods>::xDeviceCharacteristics),
        xShmMap: Some(x_shm_map),
        xShmLock: Some(x_shm_lock),
        xShmBarrier: Some(x_shm_barrier),
        xShmUnmap: Some(x_shm_unmap),
        xFetch: None,
        xUnfetch: None,
    };
}

#[derive(Clone, Copy, Default)]
struct EncVfs;

impl SQLiteVfs<EncIo> for EncVfs {
    const VERSION: i32 = 1;
    fn sleep(dur: Duration) {
        std::thread::sleep(dur);
    }
    fn random(buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }
    fn epoch_timestamp_in_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// URI fuer rusqlite (VFS wird pro Pfad mit dem DB-Key angemeldet).
pub fn uri(path: &Path) -> String {
    format!("file:{}?vfs={VFS_NAME}", path.display())
}

#[allow(dead_code)]
fn _unused(_: &VfsAppData<Mutex<HashMap<String, EncFile>>>) {}
