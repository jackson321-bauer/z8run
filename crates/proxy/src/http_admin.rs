//! Admin-Router: NUR ueber den 0600-Admin-UDS erreichbar.

use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use proxy_kern::meta::EventKind;
use serde::Deserialize;
use serde_json::Value;

use crate::adapters::login;
use crate::http::ApiError;
use crate::service::ProxyService;

async fn admin_session(
    State(svc): State<Arc<ProxyService>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let open_dbs = body
        .get("open_dbs")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reply = login::open_session(&svc, &body, open_dbs).await?;
    Ok(Json(reply))
}

#[derive(Deserialize)]
struct MetaReq {
    action: String,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    object_ref: Option<String>,
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

/// Hook fuer z8run/Engine/Blob-Manager: meldet eine Aktion als Meta-Ereignis.
/// Nur ueber den Admin-UDS (0600) erreichbar; kein Inhalt im detail.
async fn admin_meta(
    State(svc): State<Arc<ProxyService>>,
    Json(req): Json<MetaReq>,
) -> Result<Json<Value>, ApiError> {
    let kind = EventKind::parse(&req.action)
        .ok_or_else(|| proxy_kern::ProxyError::BadRequest("unbekannte Meta-Aktion".into()))?;
    let trace_id = req
        .trace_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| svc.ensure_trace(None).0.trace_id);
    let actor = req.actor.unwrap_or_else(|| "engine".into());
    let object_ref = req.object_ref.unwrap_or_default();
    let session = req.session.unwrap_or_else(|| "engine".into());
    let status = req.status.unwrap_or_else(|| "ok".into());
    let detail = req.detail.unwrap_or_else(|| req.action.clone());
    svc.record_meta(&actor, kind, &object_ref, &trace_id, &session, &status, &detail)
        .await;
    Ok(Json(serde_json::json!({"ok": true, "action": req.action, "trace_id": trace_id})))
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new()
        .route("/v1/admin/session", post(admin_session))
        .route("/v1/admin/meta/event", post(admin_meta))
}
