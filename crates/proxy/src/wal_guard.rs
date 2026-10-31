//! WAL-STRESS = SHUT-UP (F17, fail-closed): Erkennt der Proxy eine
//! WAL-Anomalie (Fehler, Timeout, Rueckstand > Schwelle), stoppt er den
//! Verkehr geordnet und geht DOWN. Kein Weiterlaufen, kein Bypass.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

const UP: u8 = 0;
const DOWN: u8 = 1;

pub struct WalGuard {
    state: AtomicU8,
    limit: u64,
    reason: Mutex<Option<String>>,
    notify: tokio::sync::Notify,
}

impl WalGuard {
    pub fn new(pending_limit: u64) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(UP),
            limit: pending_limit,
            reason: Mutex::new(None),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub fn is_down(&self) -> bool {
        self.state.load(Ordering::SeqCst) != UP
    }

    pub fn reason(&self) -> Option<String> {
        self.reason.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Geordneter Stopp: erster Ausloeser gewinnt, Grund wird festgehalten.
    pub fn trigger(&self, reason: &str) {
        if self
            .state
            .compare_exchange(UP, DOWN, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            *self.reason.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason.to_string());
            self.notify.notify_waiters();
        }
    }

    /// Nach jedem WAL-relevanten Schreibvorgang aufrufen.
    pub fn observe(&self, pending: u64, error: Option<&str>) {
        if let Some(err) = error {
            self.trigger(&format!("WAL-Fehler: {err}"));
        } else if pending > self.limit {
            self.trigger(&format!("WAL-Rueckstand {pending} > Schwelle {}", self.limit));
        }
    }

    /// Wartet, bis der Proxy down geht (Serve-Loop bricht dann geordnet ab).
    pub async fn wait_down(&self) {
        if self.is_down() {
            return;
        }
        self.notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fehler_und_rueckstand_stoppen() {
        let g = WalGuard::new(10);
        assert!(!g.is_down());
        g.observe(0, Some("upload timeout"));
        assert!(g.is_down());
        assert!(g.reason().unwrap().contains("timeout"));
        // Idempotent: erster Grund bleibt.
        g.trigger("spaeter");
        assert!(g.reason().unwrap().contains("timeout"));
    }

    #[test]
    fn rueckstand_ueber_schwelle_stoppt() {
        let g = WalGuard::new(10);
        g.observe(10, None);
        assert!(!g.is_down());
        g.observe(11, None);
        assert!(g.is_down());
    }
}
