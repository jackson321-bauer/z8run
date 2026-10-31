//! HTTP-Endpunkte fuer Apps und den (attrappierten) LLM-Call.

use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value;

use crate::http::{bearer, ApiError};
use crate::service::ProxyService;

#[derive(Deserialize)]
struct AppCallReq {
    app: String,
    #[serde(default)]
    input: Value,
}

#[derive(Deserialize)]
struct LlmCallReq {
    prompt: String,
    user: String,
}

async fn apps(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let list = svc.app_list(&token)?;
    Ok(Json(serde_json::json!({ "apps": list })))
}

async fn app_call(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<AppCallReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let trace = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let out = svc.app_call_traced(&token, &req.app, &req.input, trace).await?;
    Ok(Json(serde_json::to_value(out).unwrap_or_default()))
}

async fn llm_call(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<LlmCallReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let trace = headers.get("traceparent").and_then(|v| v.to_str().ok());
    let out = svc.llm_call_traced(&token, &req.prompt, &req.user, trace).await?;
    Ok(Json(out))
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new()
        .route("/v1/apps", get(apps))
        .route("/v1/app/call", post(app_call))
        .route("/v1/llm/call", post(llm_call))
}
