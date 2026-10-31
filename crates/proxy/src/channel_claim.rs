//! Claim-Regeln (G3): Claim gehoert einer IDENTITAET, nicht nur einem Socket.
//! Reconnect derselben Identitaet erbt den Claim innerhalb des Grace-Fensters;
//! fremde Identitaet wird abgewiesen; Diebstahl nur explizit durch Release.

use proxy_kern::ProxyError;

use crate::channel::{ChannelRegistry, Claim, ClaimGrant};

impl ChannelRegistry {
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
        // G18: Kanaele je Identitaet begrenzen (nur Schreib-Kanaele zaehlen).
        let eigene = inner
            .channels
            .values()
            .filter(|c| {
                c.claim
                    .as_ref()
                    .is_some_and(|cl| cl.identity == identity)
            })
            .count();
        let schon = inner
            .channels
            .get(name)
            .and_then(|c| c.claim.as_ref())
            .is_some_and(|cl| cl.identity == identity);
        if !schon && eigene >= self.cfg.channels_per_session {
            return Err(ProxyError::BadRequest("Kanal-Limit je Identitaet".into()));
        }
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
        Ok(ClaimGrant {
            channel: name.to_string(),
            identity: identity.to_string(),
            stream_id: c.id,
        })
    }

    /// Ist `identity` der aktuelle Claim-Inhaber von `name`? (Senderecht)
    pub fn may_publish(&self, name: &str, identity: &str) -> bool {
        self.lock()
            .channels
            .get(name)
            .and_then(|c| c.claim.as_ref())
            .is_some_and(|cl| cl.identity == identity)
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
}
