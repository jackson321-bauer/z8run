//! Logging-Persistenz als echter Abonnent der Subscribe/Push-Naht.

use std::sync::Arc;

use async_trait::async_trait;
use proxy_kern::MetaEvent;

use crate::meta::MetaStore;
use crate::otel::OtelStore;
use crate::subscribe::{Event, Sink};

/// Logging-Persistenz als Abonnent der Subscribe/Push-Naht.
pub(crate) struct LoggingSink {
    pub(crate) meta: Arc<MetaStore>,
    pub(crate) otel: Arc<OtelStore>,
}

#[async_trait]
impl Sink for LoggingSink {
    async fn deliver(&self, event: &Event) -> bool {
        if event.kind.starts_with("meta:") {
            if let Some(v) = event.payload.get("meta") {
                match serde_json::from_value::<MetaEvent>(v.clone()) {
                    Ok(m) => {
                        if let Err(e) = self.meta.record(&m).await {
                            tracing::warn!(code = e.code(), art = m.action, "Meta-Schreiben fehlgeschlagen");
                            return false;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Meta-Abonnent: Payload unlesbar");
                        return false;
                    }
                }
            }
        } else if event.kind.starts_with("otel:") {
            if let Some(v) = event.payload.get("span") {
                match serde_json::from_value::<proxy_kern::Span>(v.clone()) {
                    Ok(span) => {
                        if let Err(e) = self.otel.write(&span).await {
                            tracing::warn!(code = e.code(), "Span-Schreiben fehlgeschlagen");
                            return false;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "OTel-Abonnent: Payload unlesbar");
                        return false;
                    }
                }
            }
        }
        true
    }
}

