//! App- und LLM-API: Apps sehen NIE Prompts; LLM-Antworten werden von
//! Prompt-Inhalt befreit, bevor sie den Aufrufer erreichen.
//! Jede Aktion erzeugt Meta + (wo moeglich) einen OTel-Span im selben Trace.

use proxy_kern::{meta::EventKind, AppCallResult, AppInfo, Direction, ProxyError, SpanStatus};
use serde_json::Value;

use crate::apps::redact_value;
use crate::service::ProxyService;

impl ProxyService {
    pub fn app_list(&self, token: &str) -> Result<Vec<AppInfo>, ProxyError> {
        self.authenticate(token)?;
        Ok(self.apps.list())
    }

    pub fn app_call(
        &self,
        token: &str,
        app_name: &str,
        input: &Value,
    ) -> Result<AppCallResult, ProxyError> {
        let info = self.authenticate(token)?;
        let app = self.apps.get(app_name)?;
        let reply = app.handle(input)?;
        let name = app.name().to_string();
        self.sessions.with(&info.session_id, |s| s.add_app(&name));
        Ok(AppCallResult {
            app: name,
            payload: reply.payload,
            stream_len: reply.stream.as_ref().map(|b| b.len()),
        })
    }

    /// Wie `app_call`, schreibt aber Meta + Span mit durchgereichter Trace.
    pub async fn app_call_traced(
        &self,
        token: &str,
        app_name: &str,
        input: &Value,
        traceparent: Option<&str>,
    ) -> Result<AppCallResult, ProxyError> {
        let info = self.authenticate(token)?;
        let (ctx, _) = self.ensure_trace(traceparent);
        let start = self.now_ms();
        let app = self.apps.get(app_name)?;
        let reply = match app.handle(input) {
            Ok(r) => r,
            Err(e) => {
                self.record_meta(
                    "app", EventKind::AppCall, app_name, &ctx.trace_id,
                    &info.session_id, "fail", "app_call",
                )
                .await;
                let mut span = proxy_kern::otel::child_span(
                    &ctx, &crate::adapters::OsRandom, "app.call", Direction::Internal, start,
                );
                span.end_ms = self.now_ms();
                span.status = SpanStatus::Error;
                span.attrs = serde_json::json!({"app": app_name, "error": e.code()});
                self.write_span(span).await;
                return Err(e);
            }
        };
        let name = app.name().to_string();
        self.sessions.with(&info.session_id, |s| s.add_app(&name));
        self.record_meta(
            "app", EventKind::AppCall, app_name, &ctx.trace_id,
            &info.session_id, "ok", "app_call",
        )
        .await;
        let mut span = proxy_kern::otel::child_span(
            &ctx, &crate::adapters::OsRandom, "app.call", Direction::Internal, start,
        );
        span.end_ms = self.now_ms();
        span.engine_id = name.clone();
        span.attrs = serde_json::json!({"app": name});
        self.write_span(span).await;
        Ok(AppCallResult {
            app: name,
            payload: reply.payload,
            stream_len: reply.stream.as_ref().map(|b| b.len()),
        })
    }

    pub async fn llm_call(
        &self,
        token: &str,
        prompt_name: &str,
        user_msg: &str,
    ) -> Result<Value, ProxyError> {
        self.llm_call_traced(token, prompt_name, user_msg, None).await
    }

    /// LLM-Aufruf mit Trace-Propagation (API-Antwort/KI-Aufruf = out).
    pub async fn llm_call_traced(
        &self,
        token: &str,
        prompt_name: &str,
        user_msg: &str,
        traceparent: Option<&str>,
    ) -> Result<Value, ProxyError> {
        let info = self.authenticate(token)?;
        let (ctx, _) = self.ensure_trace(traceparent);
        let start = self.now_ms();
        let system = self.prompts.get(prompt_name)?;
        let text = core::str::from_utf8(&system)
            .map_err(|e| ProxyError::Internal(format!("Prompt kein UTF-8: {e}")))?;
        let result = self.llm.complete(text, user_msg).await;
        let status = if result.is_ok() { "ok" } else { "fail" };
        self.record_meta(
            "engine", EventKind::CallHappened, prompt_name, &ctx.trace_id,
            &info.session_id, status, "llm_call",
        )
        .await;
        let mut span = proxy_kern::otel::child_span(
            &ctx, &crate::adapters::OsRandom, "llm.call", Direction::Out, start,
        );
        span.end_ms = self.now_ms();
        span.attrs = serde_json::json!({"prompt": prompt_name, "model": "mock"});
        if result.is_err() {
            span.status = SpanStatus::Error;
        }
        self.write_span(span).await;
        let mut out = result?;
        redact_value(&mut out, text);
        if let Value::Object(map) = &mut out {
            map.insert("trace_id".into(), Value::from(ctx.trace_id));
        }
        Ok(out)
    }
}
