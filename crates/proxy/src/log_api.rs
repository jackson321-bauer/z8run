//! Trace-Abfrage (S6-Beweiswerkzeug) + Export ueber die Service-Naht.

use proxy_kern::{ProxyError, Span};
use serde_json::Value;

use crate::export::{export, ExportOptions};
use crate::service::ProxyService;

impl ProxyService {
    pub async fn span_query(&self, trace_id: &str) -> Result<Vec<Span>, ProxyError> {
        let Some(otel) = &self.otel else {
            return Ok(Vec::new());
        };
        otel.query_trace(trace_id).await
    }

    pub async fn meta_query(
        &self,
        trace_id: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> Result<Value, ProxyError> {
        let Some(meta) = &self.meta else {
            return Ok(serde_json::json!([]));
        };
        let events = meta.query(trace_id, action, limit).await?;
        serde_json::to_value(events).map_err(|e| ProxyError::Internal(format!("meta: {e}")))
    }

    /// EIN Trace ueber BEIDE Welten: alle Spans + Metas in einer Antwort.
    pub async fn trace_full(&self, trace_id: &str) -> Result<Value, ProxyError> {
        let spans = self.span_query(trace_id).await?;
        let metas = self.meta_query(Some(trace_id), None, 100_000).await?;
        Ok(serde_json::json!({
            "trace_id": trace_id,
            "spans": spans,
            "meta": metas,
            "span_count": spans.len(),
            "meta_count": metas.as_array().map(|a| a.len()).unwrap_or(0),
        }))
    }

    pub async fn export_otel(&self, trace_id: Option<&str>) -> Result<Value, ProxyError> {
        let (Some(otel), Some(meta)) = (&self.otel, &self.meta) else {
            return Err(ProxyError::Internal("Logging-DBs nicht konfiguriert".into()));
        };
        let key = decode_key(&self.cfg.export_key)?;
        let opts = ExportOptions {
            dir: self.cfg.export_dir.clone(),
            seal_key: key,
            trace_id: trace_id.map(|s| s.to_string()),
        };
        export(otel, meta, &opts).await
    }
}

fn decode_key(raw: &str) -> Result<Vec<u8>, ProxyError> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(ProxyError::Internal("KV_PROXY_EXPORT_KEY fehlt".into()));
    }
    let hexs = t.strip_prefix("0x").unwrap_or(t);
    if hexs.len() == 64 && hexs.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(hexs).map_err(|e| ProxyError::Internal(format!("Export-Key: {e}")));
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| ProxyError::Internal(format!("Export-Key: {e}")))
}
