//! Kurzlebige, rotierende Session-Tokens (PA2). Keine statischen API-Keys.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::error::ProxyError;
use crate::traits::{Clock, Random};

#[derive(Debug, Clone, Copy)]
pub struct TokenConfig {
    pub ttl_ms: u64,
    pub grace_ms: u64,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            ttl_ms: 15 * 60 * 1000,
            grace_ms: 30 * 1000,
        }
    }
}

#[derive(Serialize)]
pub struct TokenGrant {
    pub token: String,
    pub session_id: String,
    pub expires_at_ms: u64,
}

impl fmt::Debug for TokenGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenGrant")
            .field("token", &"<redacted>")
            .field("session_id", &self.session_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

struct Grant {
    session_id: String,
    expires_at: u64,
    /// Nach Rotation: Alt-Token lebt nur noch bis hier.
    grace_until: Option<u64>,
}

/// Token-Verwaltung mit Rotation. Der Kern macht kein I/O.
pub struct TokenManager {
    cfg: TokenConfig,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    grants: Mutex<HashMap<String, Grant>>,
}

impl TokenManager {
    pub fn new(cfg: TokenConfig, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Self {
        Self {
            cfg,
            clock,
            random,
            grants: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Grant>> {
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fresh_token(&self) -> String {
        let mut raw = [0u8; 32];
        self.random.fill(&mut raw);
        raw.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn make_grant(&self, session_id: &str) -> TokenGrant {
        let now = self.clock.now_ms();
        let expires_at = now.saturating_add(self.cfg.ttl_ms);
        let token = loop {
            let candidate = self.fresh_token();
            if !self.lock().contains_key(&candidate) {
                break candidate;
            }
        };
        self.lock().insert(
            token.clone(),
            Grant {
                session_id: session_id.to_string(),
                expires_at,
                grace_until: None,
            },
        );
        TokenGrant {
            token,
            session_id: session_id.to_string(),
            expires_at_ms: expires_at,
        }
    }

    pub fn issue(&self, session_id: &str) -> TokenGrant {
        self.make_grant(session_id)
    }

    fn deadline(g: &Grant) -> u64 {
        match g.grace_until {
            Some(grace) => g.expires_at.min(grace),
            None => g.expires_at,
        }
    }

    /// Prueft ein Token und liefert die Session-ID. Abgelaufene werden entfernt.
    pub fn validate(&self, token: &str) -> Result<String, ProxyError> {
        let now = self.clock.now_ms();
        let mut grants = self.lock();
        let expired = grants
            .get(token)
            .map(|g| now >= Self::deadline(g))
            .unwrap_or(true);
        if expired {
            grants.remove(token);
            return Err(ProxyError::TokenExpired);
        }
        let sid = grants
            .get(token)
            .map(|g| g.session_id.clone())
            .ok_or(ProxyError::Unauthorized)?;
        Ok(sid)
    }

    /// Rotiert das aktuelle Token: neues Token, altes stirbt nach Grace.
    pub fn rotate(&self, token: &str) -> Result<TokenGrant, ProxyError> {
        let now = self.clock.now_ms();
        let session_id = {
            let mut grants = self.lock();
            let (sid, expired, in_grace) = match grants.get(token) {
                Some(g) => (
                    g.session_id.clone(),
                    now >= Self::deadline(g),
                    g.grace_until.is_some(),
                ),
                None => return Err(ProxyError::TokenExpired),
            };
            if expired {
                grants.remove(token);
                return Err(ProxyError::TokenExpired);
            }
            if in_grace {
                return Err(ProxyError::Unauthorized);
            }
            if let Some(g) = grants.get_mut(token) {
                g.grace_until = Some(now.saturating_add(self.cfg.grace_ms));
            }
            sid
        };
        Ok(self.make_grant(&session_id))
    }

    /// Logout: toetet alle Tokens (aktuell + Grace) der Session.
    pub fn revoke_session(&self, session_id: &str) {
        self.lock().retain(|_, g| g.session_id != session_id);
    }

    pub fn logout(&self, token: &str) -> Result<String, ProxyError> {
        let sid = self.validate(token)?;
        self.revoke_session(&sid);
        Ok(sid)
    }

    pub fn active_count(&self) -> usize {
        let now = self.clock.now_ms();
        let mut grants = self.lock();
        grants.retain(|_, g| now < Self::deadline(g));
        grants.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(AtomicU64);
    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
    impl FakeClock {
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }

    struct SeqRandom(AtomicU64);
    impl Random for SeqRandom {
        fn fill(&self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                *b = (n % 251) as u8;
            }
        }
    }

    fn manager() -> (Arc<FakeClock>, TokenManager) {
        let clock = Arc::new(FakeClock(AtomicU64::new(1_000)));
        let tm = TokenManager::new(
            TokenConfig {
                ttl_ms: 1_000,
                grace_ms: 200,
            },
            clock.clone(),
            Arc::new(SeqRandom(AtomicU64::new(0))),
        );
        (clock, tm)
    }

    #[test]
    fn rotation_alt_gueltig_in_grace_danach_tot() {
        let (clock, tm) = manager();
        let first = tm.issue("s1");
        clock.advance(100);
        let second = tm.rotate(&first.token).unwrap();
        assert_ne!(first.token, second.token);
        // Mid-Grace laeuft das alte Token noch.
        assert_eq!(tm.validate(&first.token).unwrap(), "s1");
        // Nach Grace (200 ms ab Rotation) stirbt es.
        clock.advance(250);
        assert_eq!(tm.validate(&first.token), Err(ProxyError::TokenExpired));
        // Das neue bleibt gueltig.
        assert_eq!(tm.validate(&second.token).unwrap(), "s1");
    }

    #[test]
    fn grace_token_darf_nicht_erneut_rotieren() {
        let (_, tm) = manager();
        let first = tm.issue("s1");
        let second = tm.rotate(&first.token).unwrap();
        assert!(matches!(
            tm.rotate(&first.token),
            Err(ProxyError::Unauthorized)
        ));
        assert_eq!(tm.validate(&second.token).unwrap(), "s1");
    }

    #[test]
    fn logout_toetet_alle_tokens_der_session() {
        let (_, tm) = manager();
        let first = tm.issue("s1");
        let second = tm.rotate(&first.token).unwrap();
        assert_eq!(tm.logout(&second.token).unwrap(), "s1");
        assert!(tm.validate(&first.token).is_err());
        assert!(tm.validate(&second.token).is_err());
    }

    #[test]
    fn ablauf_und_falsches_token_sind_401() {
        let (clock, tm) = manager();
        let g = tm.issue("s1");
        clock.advance(1_001);
        assert_eq!(tm.validate(&g.token), Err(ProxyError::TokenExpired));
        assert_eq!(tm.validate("deadbeef"), Err(ProxyError::TokenExpired));
    }

    #[test]
    fn debug_gibt_token_nicht_preis() {
        let (_, tm) = manager();
        let g = tm.issue("s1");
        let s = format!("{g:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains(&g.token));
    }
}
