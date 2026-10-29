//! Generated CLI trigger adapter.

/// CLI runner: stdin → flow → stdout, exit code from the error field.
pub const CLI_MAIN: &str = r#"
const TRIGGER_CANVAS_ID: &str = "__TRIGGER_CANVAS_ID__";
const TRIGGER_METHOD: &str = "__TRIGGER_METHOD__";
const TRIGGER_PATH: &str = "__TRIGGER_PATH__";

fn __FN_PARSE_BODY__(raw: &str) -> Value {
    let t = raw.trim();
    if t.is_empty() {
        return Value::Null;
    }
    serde_json::from_str(t).unwrap_or_else(|_| Value::String(t.to_string()))
}

fn __FN_READ_BODY__() -> Result<Value, BoxErr> {
    if let Some(arg) = std::env::args().nth(1) {
        return Ok(__FN_PARSE_BODY__(&arg));
    }
    let mut raw = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)?;
    Ok(__FN_PARSE_BODY__(&raw))
}

__TOKIO_MAIN__
async fn main() {
    if let Err(e) = __FN_RUN__().await {
        eprintln!("z8-export: {e}");
        std::process::exit(1);
    }
}

async fn __FN_RUN__() -> Result<(), BoxErr> {
    let stored: Flow = serde_json::from_str(FLOW_JSON)?;
    let (flow, _trigger) = __FN_COMPILE__(&stored, TRIGGER_CANVAS_ID)?;

    let responders: WebhookResponders = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    init_webhook_responders(responders.clone());
    let engine = __FN_ENGINE__().await;

    let body = __FN_READ_BODY__()?;
    let trace = Uuid::now_v7();
    let payload = hook_trigger_payload(
        TRIGGER_METHOD,
        TRIGGER_PATH,
        Value::Object(Default::default()),
        Value::Object(Default::default()),
        body,
    );
    let msg = hook_trigger_message(payload, trace);

    let (tx, rx) = tokio::sync::oneshot::channel();
    responders.write().await.insert(trace, tx);
    engine.execute_with_trigger(flow, Some(msg)).await?;

    let resp = match tokio::time::timeout(std::time::Duration::from_secs(TIMEOUT_SECS), rx).await {
        Ok(Ok(r)) => r,
        _ => {
            responders.write().await.remove(&trace);
            return Err("flow produced no response (no http-out reached)".into());
        }
    };

    let failed =
        resp.status >= 400 || resp.body.get("error").map(|e| !e.is_null()).unwrap_or(false);
    println!("{}", serde_json::to_string(&resp.body)?);
    if failed {
        std::process::exit(1);
    }
    Ok(())
}
"#;
