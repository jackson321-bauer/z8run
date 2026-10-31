//! HTTP-Endpunkte fuer den gescopten DB-Zugriff (immer mit Session-Token).

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
struct QueryReq {
    db_id: String,
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
    #[serde(default = "default_true")]
    readonly: bool,
}

#[derive(Deserialize)]
struct WriteReq {
    db_id: String,
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[derive(Deserialize)]
struct DbRef {
    db_id: Option<String>,
}

fn default_true() -> bool {
    true
}

async fn query(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<QueryReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let out = svc
        .db_query(&token, &req.db_id, &req.sql, req.params, req.readonly)
        .await?;
    Ok(Json(out))
}

async fn write(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<WriteReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let out = svc
        .db_write(&token, &req.db_id, &req.sql, req.params)
        .await?;
    Ok(Json(out))
}

async fn status(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Query(q): Query<DbRef>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let out = svc.db_status(&token, q.db_id.as_deref()).await?;
    Ok(Json(out))
}

async fn schema(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Query(q): Query<DbRef>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let db = q
        .db_id
        .ok_or_else(|| ApiError::from(proxy_kern::ProxyError::BadRequest("db_id fehlt".into())))?;
    let out = svc.db_schema(&token, &db).await?;
    Ok(Json(out))
}

async fn scope(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let dbs = svc.db_scope(&token)?;
    Ok(Json(serde_json::json!({ "dbs": dbs })))
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new()
        .route("/v1/db/query", post(query))
        .route("/v1/db/write", post(write))
        .route("/v1/db/status", get(status))
        .route("/v1/db/schema", get(schema))
        .route("/v1/db/scope", get(scope))
}
