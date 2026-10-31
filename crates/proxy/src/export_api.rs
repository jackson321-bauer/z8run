//! HTTP-API des Gesamt-Exports (G12): EINE Aktion fuer MCP/UI/CLI/API.
//! Authentifiziert mit Session-Token; Ausgabe = Manifest + PQC-Container.

use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use serde_json::Value;

use crate::export_all::ExportRequest;
use crate::http::{bearer, ApiError};
use crate::service::ProxyService;

async fn export_all(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<ExportRequest>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let out = svc.export_all(&req).await?;
    Ok(Json(out))
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new().route("/v1/export/all", post(export_all))
}
