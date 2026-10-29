
use super::*;
use z8run_core::flow::Flow;

fn flow_with(config_key: &str, value: serde_json::Value) -> Flow {
    let mut flow = Flow::new("t");
    let nodes = serde_json::json!([{
        "id": "n1",
        "data": {"type": "function", "config": {config_key: value}}
    }]);
    flow.metadata.positions.insert("canvas_nodes".into(), nodes);
    flow
}

#[test]
fn catches_common_secret_shapes() {
    for key in [
        "client_secret",
        "aws_secret_access_key",
        "key_pem",
        "private_key",
        "db_password",
        "apiToken",
        "clientSecret",
        "authorization",
    ] {
        let flow = flow_with(key, serde_json::json!("plain-value"));
        assert!(!scan(&flow).is_empty(), "{key} must be caught");
    }
}

#[test]
fn allows_paths_and_references() {
    for key in ["passwordPath", "tokenPath", "pemPath", "api_key_env"] {
        let flow = flow_with(key, serde_json::json!("req.body.password"));
        assert!(scan(&flow).is_empty(), "{key} must pass");
    }
    let flow = flow_with("token", serde_json::json!("vault:my_key"));
    assert!(scan(&flow).is_empty());
    let flow = flow_with("token", serde_json::json!("$ENV:MY_KEY"));
    assert!(scan(&flow).is_empty());
}

#[test]
fn rejects_unresolvable_placeholder() {
    let flow = flow_with("token", serde_json::json!("${MY_KEY}"));
    assert!(!scan(&flow).is_empty());
}

#[test]
fn catches_top_level_nodes_and_env_vars() {
    let mut flow = Flow::new("t");
    flow.nodes.push(
        z8run_core::Node::new("n", "function")
            .with_config(serde_json::json!({"client_secret": "leak"})),
    );
    assert!(!scan(&flow).is_empty());

    let mut flow = Flow::new("t");
    flow.config
        .env_vars
        .insert("DB_PASSWORD".into(), serde_json::json!("leak"));
    assert!(!scan(&flow).is_empty());
}

#[test]
fn max_tokens_is_not_a_secret() {
    let flow = flow_with("max_tokens", serde_json::json!(1000));
    assert!(scan(&flow).is_empty());
}

#[test]
fn credentials_string_is_caught_but_name_list_is_allowed() {
    let flow = flow_with("credentials", serde_json::json!("plain-secret"));
    assert!(!scan(&flow).is_empty());

    let mut flow = Flow::new("t");
    flow.config.credentials.push("openai_api_key".to_string());
    assert!(scan(&flow).is_empty());
}
