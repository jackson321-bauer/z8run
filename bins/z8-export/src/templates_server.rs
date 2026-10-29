//! Generated mini-axum trigger adapter.

/// Server runner: mini-axum with one route per trigger.
pub const SERVER_MAIN: &str = r#"
const ROUTES: &[(&str, &str)] = &[
__ROUTES__
];
const TRIGGER_IDS: &[&str] = &[
__TRIGGER_IDS__
];

#[derive(Clone)]
struct AppState {
    engine: Arc<FlowEngine>,
    flows: Arc<Vec<Flow>>,
    responders: WebhookResponders,
}

async fn __FN_HANDLE__(st: AppState, idx: usize, req: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    match __FN_RUN_ONE__(&st, idx, req).await {
        Ok((status, body)) => (status, axum::Json(body)).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

fn __FN_PARSE_QUERY__(q: &str) -> Value {
    let mut map = serde_json::Map::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = urlencoding::decode(k).map(|s| s.into_owned()).unwrap_or_else(|_| k.to_string());
        let val = urlencoding::decode(v).map(|s| s.into_owned()).unwrap_or_else(|_| v.to_string());
        map.insert(key, Value::String(val));
    }
    Value::Object(map)
}

async fn __FN_RUN_ONE__(
    st: &AppState,
    idx: usize,
    req: axum::extract::Request,
) -> Result<(axum::http::StatusCode, Value), BoxErr> {
    let (parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let expected = ROUTES[idx].0;
    if expected != "*" && !expected.eq_ignore_ascii_case(&method) {
        return Ok((
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            serde_json::json!({"error": "method not allowed"}),
        ));
    }

    let bytes = axum::body::to_bytes(body, 16 * 1024 * 1024).await?;
    let raw = String::from_utf8_lossy(&bytes).to_string();
    let body_json = if raw.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    };

    let mut headers = serde_json::Map::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string(), Value::String(v.to_string()));
        }
    }
    let query = parts.uri.query().map(__FN_PARSE_QUERY__).unwrap_or_else(|| serde_json::json!({}));

    let trace = Uuid::now_v7();
    let payload = hook_trigger_payload(
        method,
        parts.uri.path().to_string(),
        Value::Object(headers),
        query,
        body_json,
    );
    let msg = hook_trigger_message(payload, trace);

    let (tx, rx) = tokio::sync::oneshot::channel();
    st.responders.write().await.insert(trace, tx);
    st.engine
        .execute_with_trigger(st.flows[idx].clone(), Some(msg))
        .await?;

    let resp = match tokio::time::timeout(std::time::Duration::from_secs(TIMEOUT_SECS), rx).await {
        Ok(Ok(r)) => r,
        _ => {
            st.responders.write().await.remove(&trace);
            return Err("flow produced no response (no http-out reached)".into());
        }
    };
    let status = axum::http::StatusCode::from_u16(resp.status)
        .unwrap_or(axum::http::StatusCode::OK);
    Ok((status, resp.body))
}

__HANDLERS__

#[tokio::main]
async fn main() {
    if let Err(e) = __FN_RUN__().await {
        eprintln!("z8-export: {e}");
        std::process::exit(1);
    }
}

async fn __FN_RUN__() -> Result<(), BoxErr> {
    let stored: Flow = serde_json::from_str(FLOW_JSON)?;
    let mut flows = Vec::with_capacity(TRIGGER_IDS.len());
    for id in TRIGGER_IDS {
        let (flow, _) = __FN_COMPILE__(&stored, id)?;
        flows.push(flow);
    }

    let responders: WebhookResponders = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    init_webhook_responders(responders.clone());
    let engine = __FN_ENGINE__().await;
    let state = AppState {
        engine,
        flows: Arc::new(flows),
        responders,
    };

    let mut router = axum::Router::new();
__ROUTE_REGISTRATION__
    let router = router.with_state(state);

    let bind = std::env::var("Z8_EXPORT_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("z8-export: listening on http://{bind}");
    axum::serve(listener, router).await?;
    Ok(())
}
"#;
