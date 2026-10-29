//! WASM target gate: only logic nodes are allowed.

use anyhow::{bail, Result};
use z8run_core::flow::Flow;

/// Node types that the logic-only WASM build can execute.
pub const WASM_NODE_TYPES: &[&str] = &[
    "aggregator",
    "batch",
    "conversation-memory",
    "cron-trigger",
    "csv",
    "debug",
    "delay",
    "filter",
    "function",
    "http-in",
    "http-out",
    "if-else",
    "join",
    "json",
    "loop",
    "mapper",
    "prompt-template",
    "sanitize",
    "switch",
    "text-splitter",
    "timer",
    "unix-in",
    "vector-store",
    "webhook",
    "webhook-trigger",
];

/// Rejects flows containing network/DB/crypto nodes for the WASM target.
pub fn check_wasm_supported(stored: &Flow) -> Result<()> {
    let mut rejected: Vec<String> = Vec::new();
    if let Some(nodes) = stored
        .metadata
        .positions
        .get("canvas_nodes")
        .and_then(|v| v.as_array())
    {
        for node in nodes {
            let data = &node["data"];
            let ty = data["type"]
                .as_str()
                .or_else(|| data["nodeType"].as_str())
                .unwrap_or("?");
            if !WASM_NODE_TYPES.contains(&ty) {
                let id = node["id"].as_str().unwrap_or("?");
                let label = data["label"].as_str().unwrap_or("Node");
                rejected.push(format!("'{id}' ({label}): {ty}"));
            }
        }
    }
    if rejected.is_empty() {
        Ok(())
    } else {
        bail!(
            "target wasm: folgende Nodes werden nicht unterstützt (Netz/DB/Crypto):\n  - {}",
            rejected.join("\n  - ")
        )
    }
}
