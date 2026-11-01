//! UI-Session: AutoLock (Default 300 s, 0=aus), Offline-Regel fail-closed.
//! Der Master wird beim Sperren/Shutdown genullt (zeroize).

use zeroize::Zeroize;

pub struct UiSession {
    pub autolock_sec: u64,
    pub last_activity_ms: u64,
    pub ui_session: bool,
    pending: Vec<u8>,
    online: bool,
    shutdown: bool,
}

impl UiSession {
    pub fn new(now_ms: u64) -> Self {
        Self {
            autolock_sec: 300,
            last_activity_ms: now_ms,
            ui_session: true,
            pending: Vec::new(),
            online: true,
            shutdown: false,
        }
    }

    pub fn set_autolock(&mut self, sec: u64) {
        self.autolock_sec = sec;
    }

    pub fn login(&mut self, master: Vec<u8>) {
        self.pending.zeroize();
        self.pending = master;
        self.online = true;
        self.shutdown = false;
    }

    pub fn master(&self) -> &[u8] {
        &self.pending
    }

    /// HARTER Logout: Master sofort nullen, Worker fail-closed bis Neu-Login.
    pub fn wipe(&mut self) {
        self.pending.zeroize();
        self.pending.clear();
        self.pending.shrink_to_fit();
        self.shutdown = true;
        self.online = false;
    }

    pub fn touch(&mut self, now_ms: u64) {
        self.last_activity_ms = now_ms;
    }

    /// true = gesperrt; Master ist weg.
    pub fn check_lock(&mut self, now_ms: u64) -> bool {
        if !self.ui_session || self.autolock_sec == 0 {
            return false;
        }
        if now_ms.saturating_sub(self.last_activity_ms) >= self.autolock_sec * 1000 {
            self.pending.zeroize();
            self.pending.clear();
            return true;
        }
        false
    }

    /// Messpunkt S3: ohne Kontakt = Kern SHUTDOWN (fail-closed).
    pub fn s3_probe(&mut self, ok: bool) -> bool {
        self.online = ok;
        if !ok {
            self.shutdown = true;
            self.pending.zeroize();
            self.pending.clear();
        }
        !self.shutdown
    }

    pub fn write_allowed(&self) -> bool {
        self.online && !self.shutdown
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }
}

impl Drop for UiSession {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}
