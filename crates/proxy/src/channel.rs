//! Kanal-Kern (G3/G4/G5): Registry, Claim je Identitaet, eigener Ringpuffer
//! je Abonnent, Overflow-Verwurf. Kein I/O, kein await im Publish-Pfad —
//! ein langsamer Abonnent kann andere nie blockieren (kein Head-of-Line).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use proxy_kern::{Clock, ProxyError};

use crate::subscriber::{SubState, Subscriber};

pub const SUBSCRIBERS_PER_CHANNEL: usize = 32;
pub const CHANNELS_PER_SESSION: usize = 64;
pub const CLAIM_GRACE_MS: u64 = 5_000;
pub const SUB_QUEUE: usize = 256;

#[derive(Clone, Debug)]
pub struct ChannelConfig {
    pub subscribers_per_channel: usize,
    pub channels_per_session: usize,
    pub claim_grace_ms: u64,
    pub sub_queue: usize,
    pub max_frame_bytes: usize,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            subscribers_per_channel: SUBSCRIBERS_PER_CHANNEL,
            channels_per_session: CHANNELS_PER_SESSION,
            claim_grace_ms: CLAIM_GRACE_MS,
            sub_queue: SUB_QUEUE,
            max_frame_bytes: crate::frame::MAX_FRAME_BYTES,
        }
    }
}

pub fn valid_channel(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    (parts.len() == 2 || parts.len() == 3)
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c))
        })
}

pub(crate) struct Claim {
    pub(crate) identity: String,
    pub(crate) socket_id: u64,
    pub(crate) disconnected_at_ms: Option<u64>,
}

/// Aufnahme-Senke je Kanal (G8): laeuft parallel zum Fan-out, blockiert nie.
pub trait FrameTap: Send + Sync {
    fn on_frame(&self, seq: u64, typ: u8, payload: &[u8]);
}

/// Overflow-Melder (G5): wird bei JEDEM Publish-Pfad ausgeloest, nicht nur
/// im WebSocket-Pfad. Die Senke publiziert das Meta-Ereignis stream_overflow.
pub type OverflowSink = Arc<dyn Fn(&str, u64) + Send + Sync>;

pub(crate) struct Channel {
    pub(crate) id: u32,
    pub(crate) next_seq: u64,
    pub(crate) claim: Option<Claim>,
    pub(crate) subs: Vec<Arc<Subscriber>>,
    pub(crate) tap: Option<Arc<dyn FrameTap>>,
}

pub(crate) struct Inner {
    pub(crate) channels: HashMap<String, Channel>,
    pub(crate) overflow_total: u64,
}

pub struct ChannelRegistry {
    pub(crate) cfg: ChannelConfig,
    pub(crate) clock: Arc<dyn Clock>,
    next_id: AtomicU64,
    pub(crate) inner: Mutex<Inner>,
    overflow_sink: Mutex<Option<OverflowSink>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimGrant {
    pub channel: String,
    pub identity: String,
    pub stream_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishOutcome {
    pub seq: u64,
    pub delivered: usize,
    pub overflowed: u64,
}

impl ChannelRegistry {
    pub fn new(cfg: ChannelConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            cfg,
            clock,
            next_id: AtomicU64::new(1),
            inner: Mutex::new(Inner { channels: HashMap::new(), overflow_total: 0 }),
            overflow_sink: Mutex::new(None),
        }
    }

    pub fn set_overflow_sink(&self, sink: OverflowSink) {
        *self.overflow_sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    }

    pub(crate) fn notify_overflow(&self, channel: &str, dropped: u64) {
        let sink = self
            .overflow_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(sink) = sink {
            sink(channel, dropped);
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn open(&self, name: &str) -> Result<u32, ProxyError> {
        if !valid_channel(name) {
            return Err(ProxyError::BadRequest("Kanalname ungueltig".into()));
        }
        let mut inner = self.lock();
        if let Some(c) = inner.channels.get(name) {
            return Ok(c.id);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u32;
        inner.channels.insert(
            name.to_string(),
            Channel { id, next_seq: 0, claim: None, subs: Vec::new(), tap: None },
        );
        Ok(id)
    }

    pub fn subscribe(&self, name: &str, socket_id: u64) -> Result<Arc<Subscriber>, ProxyError> {
        self.open(name)?;
        let mut inner = self.lock();
        let c = inner.channels.get_mut(name).expect("gerade geoeffnet");
        if c.subs.len() >= self.cfg.subscribers_per_channel {
            return Err(ProxyError::BadRequest("Abonnenten-Limit erreicht".into()));
        }
        let sub = Arc::new(Subscriber {
            channel: name.to_string(),
            socket_id,
            queue: Mutex::new(SubState {
                ring: VecDeque::with_capacity(self.cfg.sub_queue.min(64)),
                overflows: 0,
                closed: false,
            }),
            notify: tokio::sync::Notify::new(),
        });
        c.subs.push(sub.clone());
        Ok(sub)
    }

    pub fn unsubscribe(&self, name: &str, socket_id: u64) {
        let mut inner = self.lock();
        if let Some(c) = inner.channels.get_mut(name) {
            c.subs.retain(|s| {
                if s.socket_id == socket_id {
                    s.close();
                    false
                } else {
                    true
                }
            });
        }
    }

    pub fn set_tap(
        &self,
        name: &str,
        tap: Option<Arc<dyn FrameTap>>,
    ) -> Result<(), ProxyError> {
        self.open(name)?;
        let mut inner = self.lock();
        if let Some(c) = inner.channels.get_mut(name) {
            c.tap = tap;
            return Ok(());
        }
        Err(ProxyError::BadRequest("Kanal unbekannt".into()))
    }

    pub fn has_tap(&self, name: &str) -> bool {
        self.lock().channels.get(name).map(|c| c.tap.is_some()).unwrap_or(false)
    }

    pub fn subscriber_count(&self, name: &str) -> usize {
        self.lock().channels.get(name).map(|c| c.subs.len()).unwrap_or(0)
    }

    pub fn channel_count(&self) -> usize {
        self.lock().channels.len()
    }

    pub fn stream_id(&self, name: &str) -> Option<u32> {
        self.lock().channels.get(name).map(|c| c.id)
    }

    pub fn recv<'a>(&'a self, sub: &'a Subscriber) -> impl std::future::Future<Output = Option<Arc<[u8]>>> + 'a {
        sub.recv()
    }
}
