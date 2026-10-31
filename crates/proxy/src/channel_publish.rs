//! Publish/Fan-out (G5): EIN Frame wird in alle Abonnenten-Puffer gelegt.
//! Kein await, kein Blockieren; Overflow wird je Abonnent gezaehlt.

use std::sync::Arc;

use proxy_kern::ProxyError;

use crate::channel::{ChannelRegistry, PublishOutcome};
use crate::frame::Frame;

impl ChannelRegistry {
    pub fn publish(
        &self,
        name: &str,
        typ: u8,
        payload: Vec<u8>,
    ) -> Result<PublishOutcome, ProxyError> {
        let mut inner = self.lock();
        let c = inner
            .channels
            .get_mut(name)
            .ok_or_else(|| ProxyError::BadRequest("Kanal unbekannt".into()))?;
        let before: u64 = c.subs.iter().map(|s| s.overflows()).sum();
        let seq = c.next_seq;
        c.next_seq += 1;
        if let Some(tap) = &c.tap {
            tap.on_frame(seq, typ, &payload);
        }
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

    pub fn overflow_total(&self) -> u64 {
        self.lock().overflow_total
    }
}
