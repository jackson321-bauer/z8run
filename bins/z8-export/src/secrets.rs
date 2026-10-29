//! Hard secret gate for exported projects.
//!
//! Exported code must never contain a plaintext secret. Config values are
//! allowed to reference the vault (`"vault:key"`) or an environment variable
//! (`"$ENV:NAME"`); everything that looks like an inline secret aborts the
//! export with a hint to move it to the environment.

use anyhow::{bail, Result};
use z8run_core::flow::Flow;

/// A suspicious inline secret found in a flow config.
#[derive(Debug, Clone)]
pub struct Finding {
    pub location: String,
    pub key: String,
}

const SECRET_KEYS: [&str; 12] = [
    "access_key",
    "accesskey",
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "secretkey",
    "password",
    "passwort",
    "token",
    "auth_token",
    "bearer",
];

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase().replace('-', "_");
    // Path fields point at request data (e.g. "passwordPath" = "req.body.password")
    // and are not secrets themselves.
    if lower.ends_with("path") || lower.ends_with("_env") {
        return false;
    }
    SECRET_KEYS.contains(&lower.as_str())
}

fn is_reference(value: &str) -> bool {
    value.starts_with("vault:")
        || value.starts_with("$ENV:")
        || value.starts_with("${")
        || value.trim().is_empty()
}

fn walk(value: &serde_json::Value, location: &str, out: &mut Vec<Finding>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let loc = format!("{location}.{k}");
                if is_secret_key(k) {
                    if let Some(s) = v.as_str() {
                        if !is_reference(s) {
                            out.push(Finding {
                                location: loc.clone(),
                                key: k.clone(),
                            });
                        }
                    }
                }
                walk(v, &loc, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                walk(v, &format!("{location}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// Scans every node config (and flow-level env vars) for inline secrets.
pub fn scan(stored: &Flow) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(nodes) = stored
        .metadata
        .positions
        .get("canvas_nodes")
        .and_then(|v| v.as_array())
    {
        for node in nodes {
            let id = node["id"].as_str().unwrap_or("?");
            if let Some(config) = node.get("data").and_then(|d| d.get("config")) {
                walk(config, &format!("node {id}"), &mut out);
            }
        }
    }
    let env = serde_json::Value::Object(stored.config.env_vars.clone());
    walk(&env, "flow.env_vars", &mut out);
    out
}

/// Aborts the export if any inline secret was found.
pub fn assert_clean(stored: &Flow) -> Result<()> {
    let findings = scan(stored);
    if findings.is_empty() {
        return Ok(());
    }
    let mut msg = String::from(
        "Export aborted: inline secrets found. Move them to the environment:\n\
         set Z8_SECRET_<NAME> and reference them as \"vault:<name>\" or \"$ENV:NAME\".\n",
    );
    for f in findings {
        msg.push_str(&format!("  - {} (key '{}')\n", f.location, f.key));
    }
    bail!(msg);
}
