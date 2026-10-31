//! Admin-Router: NUR ueber den 0600-Admin-UDS erreichbar.

use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
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

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new().route("/v1/admin/session", post(admin_session))
}
