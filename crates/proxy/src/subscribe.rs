//! Subscribe/Push-Naht (F15/F16): DER PROXY PUSHT aktiv an registrierte
//! Abonnenten (fire-and-forget). Pull-Cursor "seit WAL N" ist das
//! Sicherheitsnetz fuer Wiederaufnahme nach Absturz.
//!
//! Logging ist KEIN Privileg, sondern ein Abonnement (Meta + OTel).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub cluster: Option<String>,
    pub source: Option<String>,
    pub kind: Option<String>,
}

impl Filter {
    pub fn all() -> Self {
        Self::default()
    }

    pub fn matches(&self, event: &Event) -> bool {
        self.cluster.as_ref().map_or(true, |c| c == &event.cluster)
            && self.source.as_ref().map_or(true, |s| s == &event.source)
            && self.kind.as_ref().map_or(true, |k| k == &event.kind)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub cluster: String,
    pub source: String,
    pub kind: String,
    pub trace_id: String,
    #[serde(default)]
    pub payload: Value,
}

/// Senke: liefert `true` bei Zustellung, `false` bei Absturz/Ablehnung.
pub trait Sink: Send + Sync {
    fn deliver(&self, event: &Event) -> bool;
}

impl<F> Sink for F
where
    F: Fn(&Event) -> bool + Send + Sync,
{
    fn deliver(&self, event: &Event) -> bool {
        self(event)
    }
}

struct Sub {
    filter: Filter,
    sink: Arc<dyn Sink>,
}

struct Inner {
    next_seq: u64,
    log: VecDeque<Event>,
    subs: Vec<Sub>,
    dropped: u64,
}

pub struct EventHub {
    inner: Mutex<Inner>,
    capacity: usize,
    pushed: AtomicU64,
}

impl EventHub {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_seq: 1,
                log: VecDeque::new(),
                subs: Vec::new(),
                dropped: 0,
            }),
            capacity: capacity.max(1),
            pushed: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn subscribe(&self, filter: Filter, sink: Arc<dyn Sink>) -> usize {
        let mut inner = self.lock();
        inner.subs.push(Sub { filter, sink });
        inner.subs.len() - 1
    }

    /// Fire-and-forget Push. Liefert das Event mit vergebener Sequenz.
    pub fn publish(
        &self,
        cluster: &str,
        source: &str,
        kind: &str,
        trace_id: &str,
        payload: Value,
    ) -> Event {
        let mut inner = self.lock();
        let event = Event {
            seq: inner.next_seq,
            cluster: cluster.to_string(),
            source: source.to_string(),
            kind: kind.to_string(),
            trace_id: trace_id.to_string(),
            payload,
        };
        inner.next_seq += 1;
        inner.log.push_back(event.clone());
        while inner.log.len() > self.capacity {
            inner.log.pop_front();
        }
        let mut dropped = 0u64;
        for sub in &inner.subs {
            if sub.filter.matches(&event) && !sub.sink.deliver(&event) {
                dropped += 1;
            }
        }
        inner.dropped += dropped;
        self.pushed.fetch_add(1, Ordering::Relaxed);
        event
    }

    /// Pull-Sicherheitsnetz: alle Ereignisse mit seq > cursor (Wiederaufnahme).
    pub fn since(&self, cursor: u64) -> Vec<Event> {
        self.lock()
            .log
            .iter()
            .filter(|e| e.seq > cursor)
            .cloned()
            .collect()
    }

    pub fn subscriber_count(&self) -> usize {
        self.lock().subs.len()
    }

    pub fn pushed(&self) -> u64 {
        self.pushed.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }

    pub fn last_seq(&self) -> u64 {
        self.lock().next_seq.saturating_sub(1)
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new(10_000)
    }
}
