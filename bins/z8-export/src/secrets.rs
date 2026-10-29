//! Hard secret gate for exported projects.
//!
//! Exported code must never contain a plaintext secret. Config values are
//! allowed to reference the vault (`"vault:key"`) or an environment variable
//! (`"$ENV:NAME"`); everything that looks like an inline secret aborts the
//! export with a hint to move it to the environment.
//!
//! The scanner walks the WHOLE stored flow (canvas node configs, the
//! top-level node list, flow env vars and any other nested object), because
//! `flow.json` is a serialization of that document. Path fields such as
//! `passwordPath` point at request data and are not secrets themselves.

use anyhow::{bail, Result};
use z8run_core::flow::Flow;

/// A suspicious inline secret found in a flow config.
#[derive(Debug, Clone)]
pub struct Finding {
    pub location: String,
    pub key: String,
}

/// Substrings that mark a key as a secret value. Deliberately does NOT
/// include bare `key` or plural `tokens` (so `max_tokens` stays allowed).
const SECRET_PATTERNS: &[&str] = &[
    "secret",
    "password",
    "passwort",
    "access_key",
    "accesskey",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "key_pem",
    "keypem",
    "credential",
    "bearer",
    "authorization",
    "cookie",
    "signing_key",
];

/// Token keys: exact, suffix or `*_token` forms (not `max_tokens`).
fn is_token_key(lower: &str) -> bool {
    lower == "token"
        || lower == "pem"
        || lower.ends_with("token")
        || lower.contains("_token_")
        || lower.ends_with("_token")
}

fn normalize(key: &str) -> String {
    key.to_ascii_lowercase().replace('-', "_")
}

fn is_secret_key(key: &str) -> bool {
    let lower = normalize(key);
    // Path/env fields point at request data or env names, not secret values.
    if lower.ends_with("path") || lower.ends_with("_env") || lower.ends_with("_var") {
        return false;
    }
    SECRET_PATTERNS.iter().any(|p| lower.contains(p)) || is_token_key(&lower)
}

fn is_reference(value: &str) -> bool {
    let t = value.trim();
    t.is_empty() || t.starts_with("vault:") || t.starts_with("$ENV:")
}

fn walk(value: &serde_json::Value, location: &str, out: &mut Vec<Finding>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let loc = format!("{location}.{k}");
                if is_secret_key(k) {
                    // FlowConfig.credentials is a list of vault key NAMES, not values.
                    let names_only = normalize(k) == "credentials" && v.is_array();
                    let inline = if names_only {
                        false
                    } else {
                        match v {
                            serde_json::Value::String(s) => !is_reference(s),
                            serde_json::Value::Null => false,
                            serde_json::Value::Array(a) => a
                                .iter()
                                .any(|e| e.as_str().map(|s| !is_reference(s)).unwrap_or(true)),
                            _ => true,
                        }
                    };
                    if inline {
                        out.push(Finding {
                            location: loc.clone(),
                            key: k.clone(),
                        });
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

/// Scans the entire stored flow document for inline secrets.
pub fn scan(stored: &Flow) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(value) = serde_json::to_value(stored) {
        walk(&value, "flow", &mut out);
    }
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

#[cfg(test)]
mod tests;
