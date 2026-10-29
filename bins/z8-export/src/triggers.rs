//! Reads trigger declarations from a stored canvas flow.

use anyhow::{bail, Result};
use serde::Serialize;
use z8run_core::canvas::{normalize_hook_path, HOOK_NODE_TYPES};
use z8run_core::flow::Flow;

/// One trigger node of the canvas, normalized for codegen.
#[derive(Debug, Clone, Serialize)]
pub struct TriggerSpec {
    /// Canvas node id (matches `canvas_to_flow`'s id map).
    pub canvas_id: String,
    /// Core node type (`http-in`, `unix-in`, ...).
    pub node_type: String,
    /// Uppercased HTTP method.
    pub method: String,
    /// Normalized sub-path (`/setup`).
    pub path: String,
}

/// Collects all HTTP/unix triggers from the canvas, rejecting duplicate
/// method + path combinations (an ambiguous route can never be dispatched).
pub fn collect_triggers(stored: &Flow) -> Result<Vec<TriggerSpec>> {
    let nodes = stored
        .metadata
        .positions
        .get("canvas_nodes")
        .and_then(|v| v.as_array());

    let Some(nodes) = nodes else {
        bail!("flow has no canvas nodes; save it in the editor first");
    };

    let mut out: Vec<TriggerSpec> = Vec::new();
    for node in nodes {
        let data = &node["data"];
        let node_type = data["type"]
            .as_str()
            .or_else(|| data["nodeType"].as_str())
            .unwrap_or("");
        if !HOOK_NODE_TYPES.contains(&node_type) {
            continue;
        }
        let Some(canvas_id) = node["id"].as_str().filter(|s| !s.is_empty()) else {
            continue;
        };

        let config = &data["config"];
        let method = config["method"].as_str().unwrap_or("POST").to_uppercase();
        let path = normalize_hook_path(config["path"].as_str().unwrap_or("/"));

        if let Some(existing) = out.iter().find(|t| t.method == method && t.path == path) {
            bail!(
                "duplicate trigger route {method} {path}: nodes '{}' and '{canvas_id}'",
                existing.canvas_id
            );
        }
        out.push(TriggerSpec {
            canvas_id: canvas_id.to_string(),
            node_type: node_type.to_string(),
            method,
            path,
        });
    }

    if out.is_empty() {
        bail!("flow has no trigger node (http-in, unix-in, webhook, webhook-trigger)");
    }
    Ok(out)
}
