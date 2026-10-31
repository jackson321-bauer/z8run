//! Meta-/Trace-Schreibpfade ueber die Naht (logging ist Abonnent).

use serde_json::Value;
use proxy_kern::{EventKind, MetaEvent, TraceContext};

use crate::service::ProxyService;

impl ProxyService {
    /// Jede Aktion erzeugt mind. einen Meta-Eintrag (best effort, nie
    /// inhaltlich: detail ist Kurz-Kontext).
    pub async fn record_meta(
        &self,
        actor: &str,
        kind: EventKind,
        object_ref: &str,
        trace_id: &str,
        session: &str,
        status: &str,
        detail: &str,
    ) {
        let event = match MetaEvent::new(
            actor,
            kind,
            object_ref,
            trace_id,
            session,
            status,
            detail,
            self.now_ms(),
        ) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(code = e.code(), "Meta-Ereignis ungueltig");
                return;
            }
        };
        // Logging ist erster Abonnent an der Naht (kein Sonderpfad).
        let payload = serde_json::json!({
            "meta": serde_json::to_value(&event).unwrap_or(Value::Null)
        });
        self.hub
            .publish(
                &self.cfg.cluster_id,
                "proxy",
                &format!("meta:{}", event.action),
                trace_id,
                payload,
            )
            .await;
    }

    /// Proxy garantiert Trace: gueltiger eingehender Kontext wird
    /// durchgereicht, sonst selbst erzeugt+injiziert.
    pub fn ensure_trace(&self, incoming: Option<&str>) -> (TraceContext, bool) {
        let random = crate::adapters::OsRandom;
        proxy_kern::otel::ensure_context(incoming, &random)
    }

    pub async fn write_span(&self, span: proxy_kern::Span) {
        let payload = serde_json::json!({
            "span": serde_json::to_value(&span).unwrap_or(Value::Null)
        });
        self.hub
            .publish(
                &self.cfg.cluster_id,
                "proxy",
                &format!("otel:{}", span.name),
                &span.trace_id,
                payload,
            )
            .await;
    }

}
