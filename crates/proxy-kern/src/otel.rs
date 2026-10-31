//! OTLP/W3C-kompatible Trace-Primitive (eigen gebaut, kein Fremd-SDK).
//! Target-sauber: erzeugt/parst nur Strukturen, schreibt nie selbst I/O.
//!
//! Format-Regeln (W3C trace-context):
//! - trace-id: 32 Hex (128 bit), nicht alles null
//! - span-id:  16 Hex (64 bit),  nicht alles null
//! - traceparent: `00-<trace-id>-<span-id>-<flags>`

use serde::{Deserialize, Serialize};

use crate::error::ProxyError;
use crate::traits::Random;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
    Internal,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpanStatus {
    Ok,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub sampled: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Span {
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub attrs: serde_json::Value,
    pub start_ms: u64,
    pub end_ms: u64,
    pub status: SpanStatus,
    #[serde(default)]
    pub engine_id: String,
    #[serde(default)]
    pub direction: Option<Direction>,
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn not_zero(s: &str) -> bool {
    s.chars().any(|c| c != '0')
}

/// 128-bit Zufalls-Trace-ID (nie alles null).
pub fn new_trace_id(random: &dyn Random) -> String {
    let mut buf = [0u8; 16];
    loop {
        random.fill(&mut buf);
        if buf.iter().any(|b| *b != 0) {
            return hex_of(&buf);
        }
    }
}

/// 64-bit Zufalls-Span-ID (nie alles null).
pub fn new_span_id(random: &dyn Random) -> String {
    let mut buf = [0u8; 8];
    loop {
        random.fill(&mut buf);
        if buf.iter().any(|b| *b != 0) {
            return hex_of(&buf);
        }
    }
}

/// Neuer Wurzel-Kontext (Trace + Span).
pub fn new_context(random: &dyn Random) -> TraceContext {
    TraceContext {
        trace_id: new_trace_id(random),
        span_id: new_span_id(random),
        sampled: true,
    }
}

pub fn parse_traceparent(value: &str) -> Result<TraceContext, ProxyError> {
    let parts: Vec<&str> = value.trim().split('-').collect();
    if parts.len() != 4 {
        return Err(ProxyError::BadRequest("traceparent: 4 Felder erwartet".into()));
    }
    let (version, trace_id, span_id, flags) = (parts[0], parts[1], parts[2], parts[3]);
    if version.len() != 2 || !is_hex(version) || version == "ff" {
        return Err(ProxyError::BadRequest("traceparent: Version ungueltig".into()));
    }
    if trace_id.len() != 32 || !is_hex(trace_id) || !not_zero(trace_id) {
        return Err(ProxyError::BadRequest("traceparent: trace-id ungueltig".into()));
    }
    if span_id.len() != 16 || !is_hex(span_id) || !not_zero(span_id) {
        return Err(ProxyError::BadRequest("traceparent: span-id ungueltig".into()));
    }
    if flags.len() != 2 || !is_hex(flags) {
        return Err(ProxyError::BadRequest("traceparent: flags ungueltig".into()));
    }
    let sampled = u8::from_str_radix(flags, 16).map(|f| f & 1 == 1).unwrap_or(false);
    Ok(TraceContext {
        trace_id: trace_id.to_ascii_lowercase(),
        span_id: span_id.to_ascii_lowercase(),
        sampled,
    })
}

pub fn format_traceparent(ctx: &TraceContext) -> String {
    format!(
        "00-{}-{}-{}",
        ctx.trace_id,
        ctx.span_id,
        if ctx.sampled { "01" } else { "00" }
    )
}

/// Proxy-Garantie: gueltiger eingehender Kontext wird durchgereicht,
/// fehlender/kaputter wird ersetzt (Proxy injiziert selbst). Rueckgabe:
/// (Kontext, war_ersetzt).
pub fn ensure_context(incoming: Option<&str>, random: &dyn Random) -> (TraceContext, bool) {
    match incoming.map(parse_traceparent) {
        Some(Ok(ctx)) => (ctx, false),
        _ => (new_context(random), true),
    }
}

/// Kind-Span an einem bestehenden Kontext erzeugen.
pub fn child_span(
    parent: &TraceContext,
    random: &dyn Random,
    name: &str,
    direction: Direction,
    start_ms: u64,
) -> Span {
    Span {
        trace_id: parent.trace_id.clone(),
        span_id: new_span_id(random),
        parent_span_id: Some(parent.span_id.clone()),
        name: name.to_string(),
        attrs: serde_json::json!({}),
        start_ms,
        end_ms: start_ms,
        status: SpanStatus::Ok,
        engine_id: String::new(),
        direction: Some(direction),
    }
}

/// Bekannte Built-in-Engines, deren OTel-Faehigkeit im Engine-Register
/// deklariert ist. Unbekannte String-Engines werden NICHT pauschal erlaubt.
pub const BUILTIN_OTEL_ENGINES: &[&str] = &["demo", "fts5", "vec0"];

/// Engine-Plugin-Gate: Jede Engine muss OTel-Faehigkeit deklarieren.
/// Strings sind nur fuer die bekannten Built-ins zugelassen; Objekt-Engines
/// MUESSEN `otel` oder `spans` wahr setzen. Alles andere = abgelehnt.
pub fn check_engine_otel(engines: &serde_json::Value) -> Result<(), ProxyError> {
    let list = match engines {
        serde_json::Value::Null => return Ok(()),
        serde_json::Value::Array(a) => a,
        _ => return Err(ProxyError::BadRequest("engines muss Liste sein".into())),
    };
    for engine in list {
        let ok = match engine {
            serde_json::Value::String(name) => BUILTIN_OTEL_ENGINES.contains(&name.as_str()),
            serde_json::Value::Object(o) => {
                o.get("otel").and_then(|v| v.as_bool()).unwrap_or(false)
                    || o.get("spans").and_then(|v| v.as_bool()).unwrap_or(false)
            }
            _ => false,
        };
        if !ok {
            return Err(ProxyError::BadRequest(
                "Engine ohne OTel-Deklaration abgelehnt".into(),
            ));
        }
    }
    Ok(())
}

impl Span {
    /// Fuer den DB-Writer: eine JSON-Zeile ohne Zeilenumbruch.
    pub fn to_line(&self) -> Result<String, ProxyError> {
        serde_json::to_string(self).map_err(|e| ProxyError::Internal(format!("span json: {e}")))
    }

    pub fn from_line(line: &str) -> Result<Self, ProxyError> {
        serde_json::from_str(line)
            .map_err(|e| ProxyError::Internal(format!("span parse: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Seq(u8);
    impl Random for Seq {
        fn fill(&self, buf: &mut [u8]) {
            for b in buf {
                self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }

    #[test]
    fn traceparent_roundtrip() {
        let r = Seq(1);
        let ctx = new_context(&r);
        let header = format_traceparent(&ctx);
        assert_eq!(parse_traceparent(&header).unwrap(), ctx);
    }

    #[test]
    fn kaputter_traceparent_wird_ersetzt() {
        let r = Seq(9);
        let (ctx, replaced) = ensure_context(Some("00-zz-11-01"), &r);
        assert!(replaced);
        assert_eq!(ctx.trace_id.len(), 32);
    }

    #[test]
    fn gate_lehnt_engine_ohne_otel_ab() {
        assert!(check_engine_otel(&serde_json::json!(["demo", "fts5"])).is_ok());
        assert!(
            check_engine_otel(&serde_json::json!(["unbekannt"])).is_err(),
            "Unbekannte String-Engine ohne OTel-Deklaration muss abgelehnt werden"
        );
        assert!(
            check_engine_otel(&serde_json::json!([{"name": "neu"}])).is_err(),
            "Engine ohne OTel-Deklaration muss abgelehnt werden"
        );
        assert!(check_engine_otel(&serde_json::json!([{"name": "neu", "otel": true}])).is_ok());
    }

    #[test]
    fn span_zeile_roundtrip() {
        let r = Seq(3);
        let ctx = new_context(&r);
        let mut span = child_span(&ctx, &r, "chat", Direction::Out, 10);
        span.end_ms = 20;
        span.attrs = serde_json::json!({"model": "demo"});
        let line = span.to_line().unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(Span::from_line(&line).unwrap(), span);
    }
}
