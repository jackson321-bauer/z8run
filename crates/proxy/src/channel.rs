//! Kanal-Kern (G3/G4/G5): Registry, Claim je Identitaet, eigener Ringpuffer
//! je Abonnent, Overflow-Verwurf. Kein I/O, kein await im Publish-Pfad —
//! ein langsamer Abonnent kann andere nie blockieren (kein Head-of-Line).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use proxy_kern::{Clock, ProxyError};

use crate::frame::Frame;

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
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            subscribers_per_channel: SUBSCRIBERS_PER_CHANNEL,
            channels_per_session: CHANNELS_PER_SESSION,
            claim_grace_ms: CLAIM_GRACE_MS,
            sub_queue: SUB_QUEUE,
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

struct Claim {
    identity: String,
    socket_id: u64,
    disconnected_at_ms: Option<u64>,
}

/// Eigenes Ausgangspuffer je Abonnent. `publish` sperrt nur kurz und wirft
/// bei vollem Puffer die AELTESTEN Frames weg (Live vor Vollstaendigkeit).
pub struct Subscriber {
    pub channel: String,
    pub socket_id: u64,
    queue: Mutex<SubState>,
    notify: tokio::sync::Notify,
}

struct SubState {
    ring: VecDeque<Arc<[u8]>>,
    overflows: u64,
    closed: bool,
}

impl Subscriber {
    pub fn channel(&self) -> &str {
        &self.channel
    }

    pub fn overflows(&self) -> u64 {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).overflows
    }

    pub fn depth(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).ring.len()
    }

    pub fn close(&self) {
        let mut st = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        st.closed = true;
        drop(st);
        self.notify.notify_waiters();
    }

    async fn recv(&self) -> Option<Arc<[u8]>> {
        loop {
            let notified = self.notify.notified();
            {
                let mut st = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(frame) = st.ring.pop_front() {
                    return Some(frame);
                }
                if st.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    fn push(&self, frame: Arc<[u8]>, cap: usize) -> bool {
        let mut st = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if st.closed {
            return false;
        }
        if st.ring.len() >= cap.max(1) {
            st.ring.pop_front();
            st.overflows += 1;
        }
        st.ring.push_back(frame);
        drop(st);
        self.notify.notify_one();
        true
    }
}

struct Channel {
    id: u32,
    next_seq: u64,
    claim: Option<Claim>,
    subs: Vec<Arc<Subscriber>>,
}

struct Inner {
    channels: HashMap<String, Channel>,
    overflow_total: u64,
}

pub struct ChannelRegistry {
    cfg: ChannelConfig,
    clock: Arc<dyn Clock>,
    next_id: AtomicU64,
    inner: Mutex<Inner>,
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
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
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
            Channel { id, next_seq: 0, claim: None, subs: Vec::new() },
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

    /// Claim gehoert einer IDENTITAET. Reconnect derselben Identitaet erbt
    /// den Claim innerhalb des Grace-Fensters; fremde Identitaet wird
    /// abgewiesen, solange der Claim aktiv oder im Grace-Fenster ist.
    pub fn claim(
        &self,
        name: &str,
        identity: &str,
        socket_id: u64,
    ) -> Result<ClaimGrant, ProxyError> {
        self.open(name)?;
        if identity.is_empty() {
            return Err(ProxyError::BadRequest("Claim ohne Identitaet".into()));
        }
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let c = inner.channels.get_mut(name).expect("gerade geoeffnet");
        if let Some(claim) = &c.claim {
            if claim.identity != identity {
                let grace_active = claim
                    .disconnected_at_ms
                    .map(|t| now.saturating_sub(t) < self.cfg.claim_grace_ms)
                    .unwrap_or(true);
                if grace_active {
                    return Err(ProxyError::Stream("Claim gehoert fremder Identitaet".into()));
                }
            }
        }
        c.claim = Some(Claim {
            identity: identity.to_string(),
            socket_id,
            disconnected_at_ms: None,
        });
        Ok(ClaimGrant { channel: name.to_string(), identity: identity.to_string(), stream_id: c.id })
    }

    /// Explizite Freigabe: der naechste Claim-Inhaber darf senden.
    pub fn release(&self, name: &str, identity: &str) -> Result<(), ProxyError> {
        let mut inner = self.lock();
        let c = inner
            .channels
            .get_mut(name)
            .ok_or_else(|| ProxyError::BadRequest("Kanal unbekannt".into()))?;
        match &c.claim {
            Some(cl) if cl.identity == identity => {
                c.claim = None;
                Ok(())
            }
            Some(_) => Err(ProxyError::Stream("Claim gehoert fremder Identitaet".into())),
            None => Ok(()),
        }
    }

    /// Socket weg: Claim bleibt mit Grace-Fenster fuer dieselbe Identitaet.
    pub fn disconnect(&self, name: &str, socket_id: u64) {
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        if let Some(c) = inner.channels.get_mut(name) {
            if let Some(cl) = &mut c.claim {
                if cl.socket_id == socket_id {
                    cl.disconnected_at_ms = Some(now);
                }
            }
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

    pub fn publish(&self, name: &str, typ: u8, payload: Vec<u8>) -> Result<PublishOutcome, ProxyError> {
        let mut inner = self.lock();
        let c = inner
            .channels
            .get_mut(name)
            .ok_or_else(|| ProxyError::BadRequest("Kanal unbekannt".into()))?;
        let before: u64 = c.subs.iter().map(|s| s.overflows()).sum();
        let seq = c.next_seq;
        c.next_seq += 1;
        let bytes: Arc<[u8]> = Frame::new(typ, c.id, seq, payload)?.encode()?.into();
        let mut delivered = 0;
        for sub in &c.subs {
            if sub.push(bytes.clone(), self.cfg.sub_queue) {
                delivered += 1;
            }
        }
        let after: u64 = c.subs.iter().map(|s| s.overflows()).sum();
        inner.overflow_total = inner.overflow_total.saturating_add(after - before);
        Ok(PublishOutcome { seq, delivered, overflowed: after - before })
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
