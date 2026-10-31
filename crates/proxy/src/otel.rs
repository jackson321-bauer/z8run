//! OTel-DB-Adapter: schreibt Spans als JSON-Zeilen in die otel-DB ueber
//! die DbNode-Message-Naht (WAL-gedeckt). Kein Pufferstau, kein RSS-Wachstum.

use std::sync::Arc;

use proxy_kern::{DbPort, ProxyError, Span};
use serde_json::Value;

const CREATE: &str = "CREATE TABLE IF NOT EXISTS otel_spans (\
 id INTEGER PRIMARY KEY AUTOINCREMENT, trace_id TEXT NOT NULL, span_id TEXT NOT NULL, \
 parent_id TEXT, name TEXT NOT NULL, attrs TEXT NOT NULL, start_ms INTEGER NOT NULL, \
 end_ms INTEGER NOT NULL, status TEXT NOT NULL, engine_id TEXT NOT NULL, direction TEXT NOT NULL)";
const INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_otel_trace ON otel_spans(trace_id)";
const INSERT: &str = "INSERT INTO otel_spans \
 (trace_id, span_id, parent_id, name, attrs, start_ms, end_ms, status, engine_id, direction) \
 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
const SELECT: &str = "SELECT trace_id, span_id, parent_id, name, attrs, start_ms, end_ms, \
 status, engine_id, direction FROM otel_spans";

type ErrorSink = Arc<dyn Fn(&str) + Send + Sync>;

pub struct OtelStore {
    db: Arc<dyn DbPort>,
    db_id: String,
    session_id: String,
    on_error: std::sync::Mutex<Option<ErrorSink>>,
    schema_ready: std::sync::atomic::AtomicBool,
}

impl OtelStore {
    pub fn new(db: Arc<dyn DbPort>, db_id: impl Into<String>) -> Self {
        Self {
            db,
            db_id: db_id.into(),
            session_id: "otel-writer".into(),
            on_error: std::sync::Mutex::new(None),
            schema_ready: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Span-Fehler = Meta-Ereignis (Hook wird von der Meta-Schicht gesetzt).
    pub fn set_error_sink(&self, sink: ErrorSink) {
        *self.on_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    }

    fn report(&self, msg: &str) {
        if let Some(sink) = self
            .on_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            sink(msg);
        }
    }

    pub fn db_id(&self) -> &str {
        &self.db_id
    }

    async fn exec(&self, sql: &str, params: Vec<Value>) -> Result<Value, ProxyError> {
        self.db.reserve(&self.db_id, &self.session_id).await?;
        let out = self
            .db
            .write(&self.db_id, &self.session_id, sql, params)
            .await;
        let _ = self.db.release(&self.db_id, &self.session_id).await;
        out
    }

    async fn ensure_schema(&self) -> Result<(), ProxyError> {
        if self.schema_ready.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        self.exec(CREATE, vec![]).await?;
        self.exec(INDEX, vec![]).await?;
        self.schema_ready
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub async fn write(&self, span: &Span) -> Result<(), ProxyError> {
        let attrs = serde_json::to_string(&span.attrs)
            .map_err(|e| ProxyError::Internal(format!("attrs: {e}")))?;
        let params = vec![
            Value::from(span.trace_id.clone()),
            Value::from(span.span_id.clone()),
            span.parent_span_id.clone().map(Value::from).unwrap_or(Value::Null),
            Value::from(span.name.clone()),
            Value::from(attrs),
            Value::from(span.start_ms as i64),
            Value::from(span.end_ms as i64),
            Value::from(format!("{:?}", span.status).to_lowercase()),
            Value::from(span.engine_id.clone()),
            Value::from(
                span.direction
                    .map(|d| d.as_str().to_string())
                    .unwrap_or_else(|| "internal".into()),
            ),
        ];
        let result = async {
            self.ensure_schema().await?;
            self.exec(INSERT, params).await.map(|_| ())
        }
        .await;
        if let Err(e) = &result {
            self.report(&format!("otel write: {}", e.code()));
        }
        result
    }

    pub async fn query_trace(&self, trace_id: &str) -> Result<Vec<Span>, ProxyError> {
        self.query_where(&format!("{SELECT} WHERE trace_id = ?1 ORDER BY start_ms, id"), vec![
            Value::from(trace_id),
        ])
        .await
    }

    pub async fn all(&self) -> Result<Vec<Span>, ProxyError> {
        self.query_where(&format!("{SELECT} ORDER BY start_ms, id"), vec![])
            .await
    }

    async fn query_where(&self, sql: &str, params: Vec<Value>) -> Result<Vec<Span>, ProxyError> {
        let out = self.db.query(&self.db_id, sql, params, true).await?;
        let rows = out
            .get("rows")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        rows.iter().map(row_to_span).collect()
    }
}

fn cell(row: &Value, i: usize) -> Value {
    row.get(i).cloned().unwrap_or(Value::Null)
}

fn text(row: &Value, i: usize) -> String {
    cell(row, i).as_str().unwrap_or("").to_string()
}

fn int(row: &Value, i: usize) -> u64 {
    cell(row, i).as_u64().unwrap_or(0)
}

fn row_to_span(row: &Value) -> Result<Span, ProxyError> {
    let attrs = cell(row, 4);
    let attrs = if attrs.is_string() {
        serde_json::from_str(attrs.as_str().unwrap_or("{}")).unwrap_or(Value::Null)
    } else {
        attrs
    };
    let status = match text(row, 7).as_str() {
        "error" => proxy_kern::SpanStatus::Error,
        _ => proxy_kern::SpanStatus::Ok,
    };
    let direction = match text(row, 9).as_str() {
        "in" => Some(proxy_kern::Direction::In),
        "out" => Some(proxy_kern::Direction::Out),
        _ => Some(proxy_kern::Direction::Internal),
    };
    let parent = cell(row, 2);
    Ok(Span {
        trace_id: text(row, 0),
        span_id: text(row, 1),
        parent_span_id: parent.as_str().map(|s| s.to_string()),
        name: text(row, 3),
        attrs,
        start_ms: int(row, 5),
        end_ms: int(row, 6),
        status,
        engine_id: text(row, 8),
        direction,
    })
}
