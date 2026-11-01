//! Setup-UI-Naht: NUR lokal. Ruft dieselbe Setup-Engine (`setup_kern`), die
//! auch `bins/z8-setup` und der Flow importieren — kein zweiter Setup-Code.
//! Das Passwort steht nie in Prozess-Argumenten oder Logs.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use z8run_core::nodes::setup_nodes::setup_kern;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct UserReq {
    name: String,
    password: String,
}

#[derive(Deserialize)]
pub struct InitReq {
    providers_config: String,
    bucket: Option<String>,
    prefix: Option<String>,
    space: String,
    users: Vec<UserReq>,
    setup_keys: Option<usize>,
    hw_keys: Option<usize>,
    quorum_min: Option<usize>,
    key_dir: Option<String>,
    db_dir: Option<String>,
    vec0: Option<String>,
    out: Option<String>,
    #[serde(default)]
    create_buckets: bool,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/setup-ui/v1/init", post(init))
}

/// Nur Loopback (Desktop/nativer Client) oder UDS (ConnectInfo 127.0.0.1).
fn ist_lokal(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> bool {
    addr.ip().is_loopback()
}

fn fehler(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn zeile(msg: &str) -> String {
    msg.replace(['\n', '\r'], " ")
}

/// CSRF/Origin-Schutz: ein Cross-Origin-Browser-Request darf die lokale
/// Setup-Engine nicht ausloesen. Same-Origin (Origin-Host == Host) oder
/// kein Origin (curl/CLI, lokal) sind erlaubt.
fn origin_erlaubt(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin_host = origin.split("://").nth(1).unwrap_or("");
    origin_host.eq_ignore_ascii_case(host)
}

async fn init(
    State(_state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<InitReq>,
) -> Response {
    if !ist_lokal(ConnectInfo(peer)) {
        return fehler(StatusCode::FORBIDDEN, "Setup-UI ist nur lokal erreichbar");
    }
    if !origin_erlaubt(&headers) {
        return fehler(StatusCode::FORBIDDEN, "Setup-UI: fremde Origin abgewiesen");
    }
    if body.space.trim().is_empty() || body.users.is_empty() {
        return fehler(StatusCode::BAD_REQUEST, "space und mindestens ein Benutzer sind Pflicht");
    }
    if body.users.iter().any(|u| u.name.trim().is_empty() || u.password.is_empty()) {
        return fehler(StatusCode::BAD_REQUEST, "Jeder Benutzer braucht Name und Passwort");
    }
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let out = body.out.clone();
    tokio::spawn(async move {
        let cfg = match setup_kern::cfg_aus(
            &body.providers_config,
            body.bucket.as_deref(),
            body.prefix.as_deref(),
            body.quorum_min,
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(format!("error|Provider-Config: {e}"));
                return;
            }
        };
        let targets = cfg.targets().len();
        let users: Vec<serde_json::Value> = body
            .users
            .iter()
            .map(|u| json!({ "name": u.name, "password": u.password }))
            .collect();
        let mut req = json!({
            "space": body.space,
            "users": users,
            "setupKeys": body.setup_keys.unwrap_or(3),
            "hwKeys": body.hw_keys.unwrap_or(2),
            "quorum": { "n": targets, "threshold": cfg.quorum_min() },
            "createBuckets": body.create_buckets,
        });
        if let Some(v) = body.key_dir.as_ref() { req["keyOutDir"] = json!(v); }
        if let Some(v) = body.db_dir.as_ref() { req["dbOutDir"] = json!(v); }
        if let Some(v) = body.vec0.as_ref() { req["vec0Path"] = json!(v); }
        if body.create_buckets {
            let _ = tx.send("log|Bucket-Anlage wird geprüft (Quorum)".into());
            if let Err(e) = cfg.create_buckets().await {
                let _ = tx.send(format!("error|Bucket-Anlage: {e}"));
                return;
            }
        }

        let mut send = |m: &str| {
            let _ = tx.send(format!("log|{}", zeile(m)));
        };
        match setup_kern::init_welt_mit(&cfg, &req, &mut send).await {
            Ok(resp) => {
                if let Some(path) = out.as_ref() {
                    let text = match serde_json::to_string_pretty(&resp) {
                        Ok(t) => t,
                        Err(e) => {
                            let _ = tx.send(format!("error|Setup-JSON: {e}"));
                            return;
                        }
                    };
                    if let Err(e) = std::fs::write(path, text) {
                        let _ = tx.send(format!("error|Setup-JSON schreiben: {e}"));
                        return;
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
                // NIE Setup-PEMs/Private Keys an den Browser geben: nur Namen
                // und öffentliche Adressen. Der volle JSON bleibt 0600 auf Platte.
                let users: Vec<serde_json::Value> = resp["users"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|u| json!({ "name": u["name"], "addr_user": u["addr_user"] }))
                            .collect()
                    })
                    .unwrap_or_default();
                let summary = json!({
                    "ok": true,
                    "space": resp["space"],
                    "addr_space": resp["addr_space"],
                    "users": users,
                    "files": resp["files"].as_array().map(|a| a.len()).unwrap_or(0),
                    "provider_degraded": resp["provider_degraded"],
                    "out": out,
                });
                let _ = tx.send(format!("done|{summary}"));
            }
            Err(e) => {
                let _ = tx.send(format!("error|{}", zeile(&e)));
            }
        }
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|line| (Ok::<_, std::convert::Infallible>(Event::default().data(line)), rx))
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::ist_lokal;

    #[test]
    fn nur_loopback_ist_lokal() {
        assert!(ist_lokal(axum::extract::ConnectInfo(
            "127.0.0.1:5000".parse().unwrap()
        )));
        assert!(!ist_lokal(axum::extract::ConnectInfo(
            "203.0.113.7:5000".parse().unwrap()
        )));
    }

    #[test]
    fn fremde_origin_wird_abgewiesen() {
        use axum::http::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("127.0.0.1:7711"));
        h.insert("origin", HeaderValue::from_static("http://127.0.0.1:7711"));
        assert!(super::origin_erlaubt(&h));
        h.insert("origin", HeaderValue::from_static("http://evil.example"));
        assert!(!super::origin_erlaubt(&h));
        h.remove("origin");
        assert!(super::origin_erlaubt(&h));
    }
}
