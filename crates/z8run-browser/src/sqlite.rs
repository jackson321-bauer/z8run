//! SQLite (EINGEBRANNT) + sqlite-vec im WASM. Kein dlopen, kein Loader:
//! vec registriert sich per sqlite3_auto_extension, SQLite laeuft plain,
//! die Datei-Huelle ist Z8FC1 (cipher.rs).

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::Once;

use sqlite_wasm_rs as ffi;

extern "C" {
    fn sqlite3_vec_init(
        db: *mut ffi::sqlite3,
        pz_err: *mut *mut c_char,
        api: *const ffi::sqlite3_api_routines,
    ) -> c_int;
}

static VEC: Once = Once::new();

pub fn register_vec() {
    VEC.call_once(|| unsafe {
        let _ = ffi::sqlite3_auto_extension(Some(sqlite3_vec_init));
    });
}

pub struct Db {
    p: *mut ffi::sqlite3,
}

impl Db {
    pub fn open_memory() -> Result<Self, String> {
        register_vec();
        let mut p: *mut ffi::sqlite3 = std::ptr::null_mut();
        let name = CString::new(":memory:").unwrap();
        let rc = unsafe {
            ffi::sqlite3_open_v2(
                name.as_ptr(),
                &mut p,
                ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
                std::ptr::null(),
            )
        };
        if rc != ffi::SQLITE_OK {
            return Err(format!("sqlite3_open_v2 rc={rc}"));
        }
        Ok(Self { p })
    }

    pub fn exec(&self, sql: &str) -> Result<(), String> {
        let sql = CString::new(sql).map_err(|e| e.to_string())?;
        let rc = unsafe { ffi::sqlite3_exec(self.p, sql.as_ptr(), None, std::ptr::null_mut(), std::ptr::null_mut()) };
        if rc != ffi::SQLITE_OK {
            return Err(self.err(rc));
        }
        Ok(())
    }

    pub fn query(&self, sql: &str) -> Result<Vec<Vec<String>>, String> {
        let c = CString::new(sql).map_err(|e| e.to_string())?;
        let mut stmt: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
        let rc = unsafe { ffi::sqlite3_prepare_v2(self.p, c.as_ptr(), -1, &mut stmt, std::ptr::null_mut()) };
        if rc != ffi::SQLITE_OK {
            return Err(self.err(rc));
        }
        let mut rows = Vec::new();
        loop {
            let rc = unsafe { ffi::sqlite3_step(stmt) };
            if rc == ffi::SQLITE_DONE {
                break;
            }
            if rc != ffi::SQLITE_ROW {
                unsafe { ffi::sqlite3_finalize(stmt) };
                return Err(self.err(rc));
            }
            let n = unsafe { ffi::sqlite3_column_count(stmt) };
            let mut row = Vec::with_capacity(n as usize);
            for i in 0..n {
                let t = unsafe { ffi::sqlite3_column_type(stmt, i) };
                if t == ffi::SQLITE_NULL {
                    row.push(String::new());
                    continue;
                }
                let ptr = unsafe { ffi::sqlite3_column_text(stmt, i) };
                if ptr.is_null() {
                    row.push(String::new());
                } else {
                    let s = unsafe { CStr::from_ptr(ptr.cast()) }
                        .to_string_lossy()
                        .to_string();
                    row.push(s);
                }
            }
            rows.push(row);
        }
        unsafe { ffi::sqlite3_finalize(stmt) };
        Ok(rows)
    }

    /// Plain-DB-Bytes (wird ausserhalb mit Z8FC1 versiegelt).
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let mut size: ffi::sqlite3_int64 = 0;
        let name = CString::new("main").unwrap();
        let ptr = unsafe { ffi::sqlite3_serialize(self.p, name.as_ptr(), &mut size, 0) };
        if ptr.is_null() || size <= 0 {
            return Err("serialize leer".into());
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), size as usize) };
        let out = slice.to_vec();
        unsafe { ffi::sqlite3_free(ptr.cast()) };
        Ok(out)
    }

    pub fn deserialize(&self, plain: &[u8]) -> Result<(), String> {
        let p = unsafe { ffi::sqlite3_malloc64(plain.len() as u64) };
        if p.is_null() {
            return Err("malloc".into());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(plain.as_ptr(), p.cast::<u8>(), plain.len());
        }
        let name = CString::new("main").unwrap();
        let rc = unsafe {
            ffi::sqlite3_deserialize(
                self.p,
                name.as_ptr(),
                p.cast::<u8>(),
                plain.len() as ffi::sqlite3_int64,
                plain.len() as ffi::sqlite3_int64,
                ffi::SQLITE_DESERIALIZE_FREEONCLOSE | ffi::SQLITE_DESERIALIZE_RESIZEABLE,
            )
        };
        if rc != ffi::SQLITE_OK {
            return Err(self.err(rc));
        }
        Ok(())
    }

    pub fn vec_version(&self) -> Result<String, String> {
        let rows = self.query("SELECT vec_version()")?;
        rows.first()
            .and_then(|r| r.first())
            .cloned()
            .ok_or_else(|| "vec_version leer".to_string())
    }

    fn err(&self, rc: c_int) -> String {
        let msg = unsafe {
            let p = ffi::sqlite3_errmsg(self.p);
            if p.is_null() {
                "sqlite".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().to_string()
            }
        };
        format!("sqlite rc={rc}: {msg}")
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe {
            let _ = ffi::sqlite3_close(self.p);
        }
    }
}

#[allow(dead_code)]
fn _void(_: *mut c_void) {}
