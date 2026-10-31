//! Oeffentliche Aufnahme-/Wiedergabe-API (G8): die App fordert Aufnahme an,
//! der Kanal wird parallel als Blob-Session versiegelt; Wiedergabe laeuft
//! als normale Kanal-Wiedergabe.

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::http::{bearer, ApiError};
use crate::service::ProxyService;

#[derive(Deserialize)]
struct StartReq {
    #[serde(default = "default_db")]
    db_id: String,
    channel: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    mime: Option<String>,
}

fn default_db() -> String {
    "demo".into()
}

#[derive(Deserialize)]
struct StopReq {
    channel: String,
}

#[derive(Deserialize)]
struct PlayReq {
    #[serde(default = "default_db")]
    db_id: String,
    sid: String,
    channel: String,
    #[serde(default)]
    chunk_size: Option<usize>,
}

async fn start(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<StartReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let info = svc.authenticate(&token)?;
    let owner = req.owner.unwrap_or_else(|| info.session_id.clone());
    let mime = req.mime.unwrap_or_else(|| "application/octet-stream".into());
    let _rec = svc
        .recording_start(&req.db_id, &req.channel, &owner, &mime)
        .await?;
    Ok(Json(json!({"ok": true, "recording": req.channel})))
}

async fn stop(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<StopReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let manifest = svc.recording_stop(&req.channel).await?;
    Ok(Json(json!({"ok": true, "manifest": manifest})))
}

async fn playback(
    State(svc): State<Arc<ProxyService>>,
    headers: HeaderMap,
    Json(req): Json<PlayReq>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    svc.authenticate(&token)?;
    let frames = svc
        .playback_recording(
            &req.db_id,
            &req.sid,
            &req.channel,
            req.chunk_size.unwrap_or(64 * 1024),
        )
        .await?;
    Ok(Json(json!({"ok": true, "frames": frames})))
}

pub fn router() -> Router<Arc<ProxyService>> {
    Router::new()
        .route("/v1/recording/start", post(start))
        .route("/v1/recording/stop", post(stop))
        .route("/v1/playback", post(playback))
}
