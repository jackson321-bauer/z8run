//! Meta-Ereignis-Welt (FEST 21): Ereignis-Schema, Ereignis-Decke, WORM-Regel.
//! Meta enthaelt NIE Inhaltsdaten — nur Kurz-Kontext.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProxyError;

pub const META_TABLE: &str = "meta_events";
pub const DETAIL_MAX: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Login,
    Logout,
    FlowStart,
    FlowEnd,
    AppCall,
    CallHappened,
    Export,
    BlobUpload,
    Delete,
    ReservationChange,
    ClusterOpen,
    ClusterClose,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::FlowStart => "flow_start",
            Self::FlowEnd => "flow_end",
            Self::AppCall => "app_call",
            Self::CallHappened => "call_happened",
            Self::Export => "export",
            Self::BlobUpload => "blob_upload",
            Self::Delete => "delete",
            Self::ReservationChange => "reservation_change",
            Self::ClusterOpen => "cluster_open",
            Self::ClusterClose => "cluster_close",
        }
    }

    /// Alle 12 Ereignis-Arten (Decke: kein Ereignis ist kein Ereignis).
    pub fn all() -> [EventKind; 12] {
        [
            Self::Login,
            Self::Logout,
            Self::FlowStart,
            Self::FlowEnd,
            Self::AppCall,
            Self::CallHappened,
            Self::Export,
            Self::BlobUpload,
            Self::Delete,
            Self::ReservationChange,
            Self::ClusterOpen,
            Self::ClusterClose,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaEvent {
    pub actor: String,
    pub action: String,
    pub object_ref: String,
    #[serde(default)]
    pub trace_id: String,
    #[serde(default)]
    pub session: String,
    pub status: String,
    #[serde(default)]
    pub detail: String,
    pub ts_ms: u64,
}

impl MetaEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor: &str,
        kind: EventKind,
        object_ref: &str,
        trace_id: &str,
        session: &str,
        status: &str,
        detail: &str,
        ts_ms: u64,
    ) -> Result<Self, ProxyError> {
        let event = Self {
            actor: actor.to_string(),
            action: kind.as_str().to_string(),
            object_ref: object_ref.to_string(),
            trace_id: trace_id.to_string(),
            session: session.to_string(),
            status: status.to_string(),
            detail: shorten(detail),
            ts_ms,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), ProxyError> {
        if !matches!(self.actor.as_str(), "user" | "engine" | "app" | "system") {
            return Err(ProxyError::BadRequest("Meta-actor ungueltig".into()));
        }
        if !matches!(self.status.as_str(), "ok" | "fail" | "blockiert") {
            return Err(ProxyError::BadRequest("Meta-status ungueltig".into()));
        }
        if self.detail.len() > DETAIL_MAX {
            return Err(ProxyError::BadRequest("Meta-detail zu lang".into()));
        }
        Ok(())
    }
}

fn shorten(text: &str) -> String {
    if text.chars().count() <= DETAIL_MAX {
        return text.to_string();
    }
    text.chars().take(DETAIL_MAX).collect()
}

/// Inhalts-Negativregel: `detail` darf einen bekannten Inhaltswert nie
/// enthalten (dann ist es kein Kurz-Kontext mehr).
pub fn detail_haelt_inhalt_nicht(detail: &str, content: &str) -> bool {
    content.is_empty() || !detail.contains(content)
}

/// WORM-Regel: Meta-Zeilen sind unloeschbar. Erlaubt sind nur Schreiber
/// (INSERT) und Leser (SELECT) auf der Meta-Tabelle; alles andere abgelehnt.
pub fn sql_ist_meta_worm_konform(sql: &str) -> bool {
    let up = sql.trim_start().to_ascii_uppercase();
    // Ein WORM-Trigger DARF DELETE/UPDATE nennen (er verbietet sie ja).
    if up.starts_with("CREATE TRIGGER") {
        return up.contains("RAISE");
    }
    if up.starts_with("INSERT") || up.starts_with("SELECT") || up.starts_with("CREATE") {
        // CREATE ist nur fuer Schema/Index (idempotent IF NOT EXISTS).
        return !up.starts_with("DELETE")
            && !up.starts_with("UPDATE")
            && !up.starts_with("DROP")
            && !up.starts_with("ALTER")
            && !up.contains(" DROP ")
            && !up.contains(" DELETE ");
    }
    if up.starts_with("DELETE") || up.starts_with("UPDATE") || up.starts_with("DROP")
        || up.starts_with("ALTER") || up.starts_with("TRUNCATE")
    {
        return false;
    }
    true
}

/// JSON-Zeile fuer den DB-Writer (nie mit Inhalt).
pub fn event_value(event: &MetaEvent) -> Result<Value, ProxyError> {
    serde_json::to_value(event).map_err(|e| ProxyError::Internal(format!("meta json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alle_zwölf_arten() {
        let mut seen = std::collections::HashSet::new();
        for k in EventKind::all() {
            assert!(seen.insert(k.as_str()), "Doppelte Art {}", k.as_str());
        }
        assert_eq!(seen.len(), 12);
    }

    #[test]
    fn invalid_actor_und_status() {
        assert!(MetaEvent::new("user", EventKind::Login, "s", "t", "s", "ok", "", 0).is_ok());
        assert!(MetaEvent::new("hacker", EventKind::Login, "s", "t", "s", "ok", "", 0).is_err());
        assert!(MetaEvent::new("user", EventKind::Login, "s", "t", "s", "vielleicht", "", 0).is_err());
    }

    #[test]
    fn worm_regel() {
        assert!(sql_ist_meta_worm_konform("INSERT INTO meta_events (x) VALUES (1)"));
        assert!(sql_ist_meta_worm_konform("SELECT * FROM meta_events"));
        assert!(!sql_ist_meta_worm_konform("DELETE FROM meta_events"));
        assert!(!sql_ist_meta_worm_konform("UPDATE meta_events SET x=1"));
        assert!(!sql_ist_meta_worm_konform("DROP TABLE meta_events"));
    }

    #[test]
    fn inhalt_wird_erkannt() {
        assert!(detail_haelt_inhalt_nicht("app_call echo", "streng-geheim"));
        assert!(!detail_haelt_inhalt_nicht("echo streng-geheim", "streng-geheim"));
    }
}
