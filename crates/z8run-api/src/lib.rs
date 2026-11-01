//! # z8run-api
//!
//! z8run HTTP and WebSocket server.
//! Exposes REST API for flow management
//! and WebSockets for real-time communication.

pub mod auth;
pub mod error;
pub mod execution_recorder;
pub mod front;
pub mod front_ws;
pub mod hook_limits;
pub mod rate_limit;
pub mod routes;
pub mod state;
pub mod tls;
pub mod ui;
pub mod ui_login;
pub mod ws;

use axum::http::{header, HeaderValue, Method};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use state::AppState;

/// Builds the CORS layer for the API.
///
/// Reads a comma-separated allow-list of origins from the `Z8_CORS_ORIGINS`
/// environment variable (e.g. `https://app.example.com,https://admin.example.com`).
///
/// - When set and non-empty, CORS is restricted to exactly those origins.
///   Invalid entries are skipped with a warning. A restricted origin list
///   makes credentialed requests safe, so `allow_credentials(true)` is enabled.
/// - When unset or empty, it falls back to the previous permissive policy so
///   local development is not broken, emitting a warning so this is never used
///   in production without noticing.
fn build_cors_layer() -> CorsLayer {
    let origins: Vec<HeaderValue> = std::env::var("Z8_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|origin| match origin.parse::<HeaderValue>() {
            Ok(value) => Some(value),
            Err(_) => {
                tracing::warn!(origin = origin, "Skipping invalid CORS origin");
                None
            }
        })
        .collect();

    if origins.is_empty() {
        tracing::warn!("CORS is permissive (no Z8_CORS_ORIGINS set); set it in production");
        return CorsLayer::permissive();
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true)
}

/// Cross-Origin-Isolation für den WASM-Worker (OPFS + SQLite-Atomics).
async fn isolation_headers(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::HeaderName::from_static("cross-origin-opener-policy"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    h.insert(
        axum::http::header::HeaderName::from_static("cross-origin-embedder-policy"),
        axum::http::HeaderValue::from_static("require-corp"),
    );
    // Kein veraltetes WASM im Browser-Cache (Deploy = neue Kern-Version).
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp
}

/// Builds the main application router.
pub fn build_router(state: Arc<AppState>) -> Router {
    // Initialize rate limiters from env vars
    rate_limit::init_rate_limiters();

    // Protected API routes with JWT middleware + API rate limit
    let protected_api = routes::api_routes().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::jwt_middleware,
    ));

    // Auth routes: public (/register, /login) + protected (/me)
    // Auth routes get stricter rate limiting
    let auth_router = auth::auth_routes().merge(auth::auth_protected_routes().layer(
        axum::middleware::from_fn_with_state(state.clone(), auth::jwt_middleware),
    ));

    // Public API routes (health, info) - no auth required
    let public_api = routes::public_routes();

    let router = Router::new()
        .nest(
            "/api/v1",
            protected_api
                .merge(public_api)
                .layer(axum::middleware::from_fn(rate_limit::api_rate_limit)),
        )
        .nest(
            "/auth",
            auth_router.layer(axum::middleware::from_fn(rate_limit::auth_rate_limit)),
        )
        .nest(
            "/hook",
            routes::hook_routes()
                // Public entry point: cap the body explicitly (A-06); larger
                // requests get 413 before the handler runs.
                .layer(axum::extract::DefaultBodyLimit::max(
                    state.hook_limits.max_body_bytes,
                ))
                .layer(axum::middleware::from_fn(rate_limit::hook_rate_limit)),
        )
        .nest("/ws", ws::ws_routes())
        // Dünne UI-Naht: öffentliche Weltdateien für die Login-Seite.
        .merge(ui_login::routes());

    // Browser-Buendel (/wasm/*) aus dem konfigurierten Verzeichnis; kein
    // file://-Test, echter Ursprung ueber den 443-Front.
    let router = match std::env::var("Z8_WASM_DIR") {
        Ok(dir) if !dir.trim().is_empty() => {
            // Der WASM-Worker muss wie die Wizard-Seite cross-origin-isoliert
            // sein (OPFS-SyncAccess + SharedArrayBuffer/Atomics).
            let wasm = axum::Router::new()
                .fallback_service(tower_http::services::ServeDir::new(dir))
                .layer(axum::middleware::from_fn(isolation_headers));
            router.nest("/wasm", wasm)
        }
        _ => router,
    };

    // Standalone binaries serve the web editor themselves (Docker uses Nginx).
    #[cfg(feature = "embed-ui")]
    let router = router.fallback(ui::serve);

    router
        .layer(build_cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
