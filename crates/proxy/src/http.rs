//! Kleiner nativer API-Server (localhost-TCP und UDS, gleicher Router).

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use proxy_kern::{ErrorBody, ProxyError};

use crate::service::ProxyService;

pub struct ApiError(ProxyError);

impl From<ProxyError> for ApiError {
    fn from(e: ProxyError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(ErrorBody::from_error(&self.0))).into_response()
    }
}

fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ProxyError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or(ProxyError::Unauthorized)?;
    if token.is_empty() {
        return Err(ProxyError::Unauthorized.into());
    }
    Ok(token.to_string())
}

async fn status(State(svc): State<Arc<ProxyService>>) -> Json<serde_json::Value> {
    Json(svc.status())
}

async fn session(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = bearer(&headers)?;
    let info = svc.authenticate(&token)?;
    Ok(Json(serde_json::to_value(info).unwrap_or_default()))
}

async fn rotate(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = bearer(&headers)?;
    let grant = svc.rotate(&token)?;
    Ok(Json(serde_json::json!({
        "token": grant.token,
        "session_id": grant.session_id,
        "expires_at_ms": grant.expires_at_ms,
    })))
}

async fn logout(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.logout(&token)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub fn router(svc: Arc<ProxyService>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/session", get(session))
        .route("/v1/session/rotate", post(rotate))
        .route("/v1/session/logout", post(logout))
        .with_state(svc)
}

pub async fn serve_tcp(svc: Arc<ProxyService>) -> anyhow::Result<()> {
    let addr = format!("{}:{}", svc.cfg.http_bind, svc.cfg.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(address = %addr, "Proxy HTTP bereit");
    axum::serve(listener, router(svc)).await?;
    Ok(())
}

/// Gleicher Router ueber einen Unix-Socket (Zugriff nur ueber Dateirechte).
pub async fn serve_uds(svc: Arc<ProxyService>, path: std::path::PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = tokio::fs::remove_file(&path).await;
    let uds = tokio::net::UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(path = %path.display(), "Proxy-Admin-UDS bereit");
    loop {
        let (stream, _) = uds.accept().await?;
        let app = router(svc.clone());
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let req =
                            hyper::Request::from_parts(parts, axum::body::Body::new(body));
                        match tower::ServiceExt::oneshot(app, req).await {
                            Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                            Err(e) => match e {},
                        }
                    }
                },
            );
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::warn!(error = %e, "Proxy-UDS Verbindungsfehler");
            }
        });
    }
}
