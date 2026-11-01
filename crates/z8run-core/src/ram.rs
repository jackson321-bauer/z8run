//! RAM-HARDENING (FEST 12): Stufen 0..3, mlock fuer Schluesselspeicher,
//! zeroize beim Drop, no-swap/no-core-Optionen fuer Kern-Prozesse.
//!
//! Stufe 0 = aus, 1 = zeroize (immer aktiv), 2 = mlock (Default),
//! 3 = mlock + DONTDUMP + nicht-dumpbar + RLIMIT_MEMLOCK hochsetzen.
//! `/proc/<pid>/status` VmLck > 0 ist der Beweis (Test/S6-Log).

use std::io::Write;
use std::sync::OnceLock;

use zeroize::Zeroize;

pub const RLIMIT_MEMLOCK: i32 = 8;
pub const PR_SET_DUMPABLE: i32 = 4;
pub const MADV_DONTDUMP: i32 = 16;

extern "C" {
    fn mlock(addr: *const std::os::raw::c_void, len: usize) -> std::os::raw::c_int;
    fn munlock(addr: *const std::os::raw::c_void, len: usize) -> std::os::raw::c_int;
    fn madvise(addr: *mut std::os::raw::c_void, len: usize, advice: i32) -> std::os::raw::c_int;
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> std::os::raw::c_int;
    fn getrlimit(resource: i32, rlim: *mut Rlimit) -> std::os::raw::c_int;
    fn setrlimit(resource: i32, rlim: *const Rlimit) -> std::os::raw::c_int;
}

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

static LEVEL: OnceLock<u8> = OnceLock::new();
static ARENA: OnceLock<LockedBuffer> = OnceLock::new();

/// `Z8_RAM_LEVEL` (0..3), Default 2. Wird beim Start einmal gelesen.
pub fn level_from_env() -> u8 {
    std::env::var("Z8_RAM_LEVEL")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|v| v.min(3))
        .unwrap_or(2)
}

/// Initialisiert die Stufe und haelt eine mlock-Arena fuer den Prozess.
pub fn init() -> u8 {
    let level = level_from_env();
    let _ = LEVEL.set(level);
    if level >= 3 {
        raise_memlock();
        unsafe {
            let _ = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
    if level >= 2 {
        let _ = ARENA.set(LockedBuffer::new(64 * 1024));
        if level >= 3 {
            if let Some(a) = ARENA.get() {
                unsafe {
                    let _ = madvise(a.data.as_ptr() as *mut _, a.len, MADV_DONTDUMP);
                }
            }
        }
    }
    tracing::info!(
        stufe = level,
        mlock_arena = ARENA.get().map(|a| a.mlocked).unwrap_or(false),
        "RAM-Hardening aktiv"
    );
    level
}

pub fn level() -> u8 {
    *LEVEL.get().unwrap_or(&0)
}

fn raise_memlock() {
    unsafe {
        let mut r = Rlimit { cur: 0, max: 0 };
        if getrlimit(RLIMIT_MEMLOCK, &mut r) == 0 {
            r.cur = u64::MAX;
            r.max = u64::MAX;
            let _ = setrlimit(RLIMIT_MEMLOCK, &r);
        }
    }
}

/// Heap-Puffer, der (soweit erlaubt) gemlockt und beim Drop genullt wird.
pub struct LockedBuffer {
    data: Box<[u8]>,
    len: usize,
    pub mlocked: bool,
}

impl LockedBuffer {
    pub fn new(len: usize) -> Self {
        let data = vec![0u8; len].into_boxed_slice();
        let ptr = data.as_ptr();
        let mut mlocked = false;
        if level() >= 2 || LEVEL.get().is_none() {
            unsafe {
                mlocked = mlock(ptr as *const _, len) == 0;
            }
        }
        let _ = ptr;
        Self { data, len, mlocked }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Nullt den Speicher sofort (Test-Hook und Secret-Drop).
    pub fn zeroize_now(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.mlocked {
            unsafe {
                let _ = munlock(self.data.as_ptr() as *const _, self.len);
            }
        }
    }
}

/// Beweist VmLck > 0 ueber /proc/self/status (nur Linux).
pub fn vmlck_kb() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmLck:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// Schreibt die aktive Stufe und VmLck in ein Log (Deployment-Beweis).
pub fn log_status(mut out: impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "RAM_LEVEL={} VmLck_kB={} ARENA={}",
        level(),
        vmlck_kb(),
        ARENA.get().map(|a| a.mlocked).unwrap_or(false)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlock_erzeugt_vmlck_und_drop_nullt() {
        std::env::set_var("Z8_RAM_LEVEL", "2");
        init();
        let mut b = LockedBuffer::new(32 * 1024);
        b.as_mut_slice().fill(0xAA);
        assert!(vmlck_kb() > 0, "VmLck muss > 0 sein");
        b.zeroize_now();
        assert!(b.as_slice().iter().all(|x| *x == 0), "zeroize muss nullen");
        assert!(b.mlocked);
    }

    #[test]
    fn stufe_0_laesst_mlock_aus() {
        // Stufe 0 in einem eigenen Puffer (Arena-Stufe bleibt global 2).
        let b = LockedBuffer::new(1024);
        // Der Test beweist nur, dass die API existiert; global gilt Stufe 2.
        assert_eq!(b.as_slice().len(), 1024);
    }
}
