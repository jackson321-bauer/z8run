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

    /// Parameterbelegung fuer den Kernel-Pfad (DbPort): JSON -> SQLite.
    /// Werte werden gebunden, nie in SQL interpoliert.
    fn bind_params(&self, stmt: *mut ffi::sqlite3_stmt, params: &[serde_json::Value]) -> Result<(), String> {
        for (i, v) in params.iter().enumerate() {
            let idx = (i + 1) as c_int;
            let rc = match v {
                serde_json::Value::Null => unsafe { ffi::sqlite3_bind_null(stmt, idx) },
                serde_json::Value::Bool(b) => unsafe { ffi::sqlite3_bind_int(stmt, idx, *b as c_int) },
                serde_json::Value::Number(n) => {
                    if let Some(i64v) = n.as_i64() {
                        unsafe { ffi::sqlite3_bind_int64(stmt, idx, i64v) }
                    } else {
                        unsafe { ffi::sqlite3_bind_double(stmt, idx, n.as_f64().unwrap_or(0.0)) }
                    }
                }
                serde_json::Value::String(s) => unsafe {
                    ffi::sqlite3_bind_text(
                        stmt,
                        idx,
                        s.as_ptr().cast::<c_char>(),
                        s.len() as c_int,
                        ffi::SQLITE_TRANSIENT(),
                    )
                },
                other => {
                    let s = other.to_string();
                    unsafe {
                        ffi::sqlite3_bind_text(
                            stmt,
                            idx,
                            s.as_ptr().cast::<c_char>(),
                            s.len() as c_int,
                            ffi::SQLITE_TRANSIENT(),
                        )
                    }
                }
            };
            if rc != ffi::SQLITE_OK {
                return Err(format!("bind {idx} rc={rc}"));
            }
        }
        Ok(())
    }

    /// Schreib-/DDL-Statement mit gebundenen Parametern.
    pub fn exec_params(&self, sql: &str, params: &[serde_json::Value]) -> Result<u64, String> {
        let c = CString::new(sql).map_err(|e| e.to_string())?;
        let mut stmt: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
        let rc = unsafe { ffi::sqlite3_prepare_v2(self.p, c.as_ptr(), -1, &mut stmt, std::ptr::null_mut()) };
        if rc != ffi::SQLITE_OK {
            return Err(self.err(rc));
        }
        if let Err(e) = self.bind_params(stmt, params) {
            unsafe { ffi::sqlite3_finalize(stmt) };
            return Err(e);
        }
        let rc = unsafe { ffi::sqlite3_step(stmt) };
        let changed = unsafe { ffi::sqlite3_changes(self.p) } as u64;
        unsafe { ffi::sqlite3_finalize(stmt) };
        if rc != ffi::SQLITE_DONE && rc != ffi::SQLITE_ROW {
            return Err(self.err(rc));
        }
        Ok(changed)
    }

    /// Lese-Statement mit gebundenen Parametern (JSON-Zellen).
    pub fn query_params(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<(Vec<String>, Vec<Vec<serde_json::Value>>), String> {
        let c = CString::new(sql).map_err(|e| e.to_string())?;
        let mut stmt: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
        let rc = unsafe { ffi::sqlite3_prepare_v2(self.p, c.as_ptr(), -1, &mut stmt, std::ptr::null_mut()) };
        if rc != ffi::SQLITE_OK {
            return Err(self.err(rc));
        }
        if let Err(e) = self.bind_params(stmt, params) {
            unsafe { ffi::sqlite3_finalize(stmt) };
            return Err(e);
        }
        let n = unsafe { ffi::sqlite3_column_count(stmt) };
        let mut cols = Vec::with_capacity(n as usize);
        for i in 0..n {
            let p = unsafe { ffi::sqlite3_column_name(stmt, i) };
            cols.push(if p.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string()
            });
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
            let mut row = Vec::with_capacity(n as usize);
            for i in 0..n {
                let t = unsafe { ffi::sqlite3_column_type(stmt, i) };
                row.push(match t {
                    ffi::SQLITE_NULL => serde_json::Value::Null,
                    ffi::SQLITE_INTEGER => {
                        serde_json::Value::from(unsafe { ffi::sqlite3_column_int64(stmt, i) })
                    }
                    ffi::SQLITE_FLOAT => serde_json::Value::from(unsafe {
                        ffi::sqlite3_column_double(stmt, i)
                    }),
                    _ => {
                        let p = unsafe { ffi::sqlite3_column_text(stmt, i) };
                        if p.is_null() {
                            serde_json::Value::Null
                        } else {
                            serde_json::Value::String(
                                unsafe { CStr::from_ptr(p.cast()) }.to_string_lossy().to_string(),
                            )
                        }
                    }
                });
            }
            rows.push(row);
        }
        unsafe { ffi::sqlite3_finalize(stmt) };
        Ok((cols, rows))
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
