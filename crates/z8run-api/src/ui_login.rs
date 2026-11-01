//! Login-UI-Naht: liefert die öffentlichen Weltdateien (Hashdatei + HW-Shards),
//! die die Login-Seite zum Öffnen der Boxen braucht. Schlüssel bleiben
//! serverseitig in der S3-Config; die UI sieht nur Argon2-Hash und Chiffren.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use z8run_core::nodes::setup_nodes::setup_crypto as sc;
use z8run_core::nodes::setup_nodes::setup_io::S3Cfg;

use crate::state::AppState;

const S3_CONFIG: &str = "Z8_LOGIN_S3_CONFIG";
const DEFAULT_CONFIG: &str = "/etc/z8run/kv3-s3.json";
const LOGIN_FLOW: &str = "KV3-Login-WebAuthn";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/login-ui/v1/world", get(world))
}

fn fehler(status: StatusCode, msg: impl Into<String>) -> axum::response::Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// Adressen exakt wie der Kern (setup_crypto), keine zweite Ableitung.
pub fn adressen(space: &str, user: &str) -> Result<(String, String), String> {
    let space_salt = sc::salt_space(space);
    let space_addr = sc::kette::adresse(space, &space_salt)?;
    let user_salt = sc::salt_user(&space_salt, user);
    let user_addr = sc::kette::adresse(user, &user_salt)?;
    Ok((space_addr, user_addr))
}

async fn world(
    State(state): State<Arc<AppState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let space = q.get("space").map(String::as_str).unwrap_or("").trim();
    let user = q.get("user").map(String::as_str).unwrap_or("").trim();
    if space.is_empty() || user.is_empty() {
        return fehler(StatusCode::BAD_REQUEST, "space und user sind Pflicht");
    }
    let (space_addr, user_addr) = match adressen(space, user) {
        Ok(v) => v,
        Err(e) => return fehler(StatusCode::BAD_REQUEST, format!("Adresse: {e}")),
    };
    let config = std::env::var(S3_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let cfg = match S3Cfg::aus_datei(&config) {
        Ok(c) => c,
        Err(e) => return fehler(StatusCode::SERVICE_UNAVAILABLE, format!("S3-Config: {e}")),
    };
    let b2b_key = format!("b2b/{user_addr}.txt");
    let hw_key = format!("workspaces/{user_addr}/hw-shards.txt");
    let (b2b, hw) = match (cfg.get(&b2b_key).await, cfg.get(&hw_key).await) {
        (Ok(b), Ok(h)) => (b, h),
        (Err(_), _) => return fehler(StatusCode::NOT_FOUND, "Space/Benutzer nicht gefunden"),
        (_, Err(e)) => return fehler(StatusCode::NOT_FOUND, format!("HW-Shards: {e}")),
    };
    let login_flow_id = match state.storage.list_flows().await {
        Ok(flows) => flows
            .iter()
            .find(|f| f.name == LOGIN_FLOW)
            .map(|f| f.id.to_string()),
        Err(_) => None,
    };
    Json(json!({
        "space": space,
        "user": user,
        "space_addr": space_addr,
        "user_addr": user_addr,
        "b2b": String::from_utf8_lossy(&b2b),
        "hw_shards": String::from_utf8_lossy(&hw),
        "login_flow_id": login_flow_id,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn adressen_passen_zur_bewiesenen_dev_welt() {
        let (space, user) = super::adressen("z8dev", "anna").unwrap();
        assert_eq!(space, "rhahonwdlq2ttqnliagcsrnjomdbkgjg");
        assert_eq!(user, "h533z2xxzcaznpoczlilrglbkn6wzpqz");
    }
}
