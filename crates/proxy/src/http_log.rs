//! HTTP-Endpunkte der Logging-Welten: Trace-Abfrage + JSONL-Export.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value;

use crate::http::{bearer, ApiError};
use crate::service::ProxyService;

#[derive(Deserialize)]
struct TraceReq {
    trace_id: String,
}

#[derive(Deserialize)]
struct MetaReq {
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}

#[derive(Deserialize)]
struct ExportReq {
    #[serde(default)]
    trace_id: Option<String>,
}

fn default_limit() -> usize {
    1000
}

async fn spans(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Query(q): Query<TraceReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let spans = svc.span_query(&q.trace_id).await?;
    Ok(Json(serde_json::json!({"trace_id": q.trace_id, "spans": spans})))
}

async fn meta(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<MetaReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let out = svc
        .meta_query(req.trace_id.as_deref(), req.action.as_deref(), req.limit)
        .await?;
    let count = out.as_array().map(|a| a.len()).unwrap_or(0);
    Ok(Json(serde_json::json!({"meta": out, "count": count})))
}

async fn trace_full(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Query(q): Query<TraceReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    Ok(Json(svc.trace_full(&q.trace_id).await?))
}

async fn export_otel(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<ExportReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let info = svc.authenticate(&token)?;
    let manifest = svc.export_otel(req.trace_id.as_deref()).await?;
    svc.record_meta(
        "user",
        proxy_kern::meta::EventKind::Export,
        "otel",
        req.trace_id.as_deref().unwrap_or("alle"),
        &info.session_id,
        "ok",
        "export_otel",
    )
    .await;
    Ok(Json(manifest))
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new()
        .route("/v1/spans", get(spans))
        .route("/v1/meta/query", post(meta))
        .route("/v1/trace/full", get(trace_full))
        .route("/v1/export/otel", post(export_otel))
}
