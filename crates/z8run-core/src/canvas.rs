//! Canvas → Flow compiler.
//!
//! The editor stores the visual graph inside the flow's `metadata.positions`
//! (`canvas_nodes` / `canvas_edges`). This module turns that canvas state into
//! an executable [`Flow`]. It is the single implementation used by the HTTP
//! API and by exported projects, so both compile a canvas exactly the same way.

use std::collections::HashMap;

use tracing::warn;
use uuid::Uuid;

use crate::flow::{Edge, Flow};
use crate::message::FlowMessage;
use crate::node::{Node, PortType};

/// Errors that can occur while compiling a canvas into a flow.
#[derive(Debug, thiserror::Error)]
pub enum CanvasError {
    /// The stored flow has no `canvas_nodes` in its metadata.
    #[error("No canvas nodes found. Save the flow first.")]
    NoCanvasNodes,
}

/// Converts the frontend canvas state (stored in metadata) into an executable
/// core [`Flow`] with proper Nodes and Edges.
///
/// Node configs are copied verbatim. Vault references (`"vault:key"`) are NOT
/// resolved here; callers that have a credential vault resolve them before
/// calling this function.
pub fn canvas_to_flow(stored: &Flow) -> Result<(Flow, HashMap<String, Uuid>), CanvasError> {
    let canvas_nodes = stored
        .metadata
        .positions
        .get("canvas_nodes")
        .and_then(|v| v.as_array())
        .ok_or(CanvasError::NoCanvasNodes)?;

    let canvas_edges = stored
        .metadata
        .positions
        .get("canvas_edges")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut flow = Flow::new(&stored.name);
    flow.id = stored.id;
    flow.description = stored.description.clone();

    // Namespace UUID for deterministic ID generation.
    // Same flow_id + canvas_id always produces the same core UUID,
    // so Deploy and hook trigger share the same node mapping.
    let namespace = stored.id;

    // Map canvas node IDs (strings like "node_123") to core UUIDs
    let mut id_map: HashMap<String, Uuid> = HashMap::new();

    for canvas_node in canvas_nodes {
        let canvas_id = canvas_node["id"].as_str().unwrap_or("unknown").to_string();
        let data = &canvas_node["data"];

        // Extract the node type (try "type" first, then "nodeType" for curl-created nodes)
        let node_type_str = data["type"]
            .as_str()
            .or_else(|| data["nodeType"].as_str())
            .unwrap_or("function");
        let label = data["label"].as_str().unwrap_or("Node");

        // Build core Node with appropriate ports based on type
        let mut core_node = Node::new(label, node_type_str);

        // Override with deterministic UUID: same canvas_id always → same core UUID
        core_node.id = Uuid::new_v5(&namespace, canvas_id.as_bytes());

        // Add input ports based on canvas data
        if let Some(inputs) = data["inputs"].as_array() {
            for input in inputs {
                let port_name = input["id"].as_str().unwrap_or("input");
                let port_type = parse_port_type(input["type"].as_str().unwrap_or("any"));
                core_node = core_node.with_input(port_name, port_type);
            }
        } else {
            // Default: single input
            core_node = core_node.with_input("input", PortType::Any);
        }

        // Add output ports based on canvas data
        if let Some(outputs) = data["outputs"].as_array() {
            for output in outputs {
                let port_name = output["id"].as_str().unwrap_or("output");
                let port_type = parse_port_type(output["type"].as_str().unwrap_or("any"));
                core_node = core_node.with_output(port_name, port_type);
            }
        } else {
            // Default: single output
            core_node = core_node.with_output("output", PortType::Any);
        }

        // Pass the node config through unchanged.
        if let Some(config) = data.get("config") {
            core_node = core_node.with_config(config.clone());
        }

        id_map.insert(canvas_id, core_node.id);
        flow.nodes.push(core_node);
    }

    // Convert canvas edges to core Edges
    for canvas_edge in &canvas_edges {
        let source = canvas_edge["source"].as_str().unwrap_or("");
        let target = canvas_edge["target"].as_str().unwrap_or("");
        let source_handle = canvas_edge["sourceHandle"].as_str().unwrap_or("output");
        let target_handle = canvas_edge["targetHandle"].as_str().unwrap_or("input");

        if let (Some(&from_id), Some(&to_id)) = (id_map.get(source), id_map.get(target)) {
            let edge = Edge::new(from_id, source_handle, to_id, target_handle);
            flow.edges.push(edge);
        } else {
            warn!(
                source = source,
                target = target,
                "Skipping edge with unknown nodes"
            );
        }
    }

    Ok((flow, id_map))
}

/// Parses a canvas port type string into a [`PortType`].
pub fn parse_port_type(s: &str) -> PortType {
    match s {
        "string" => PortType::String,
        "number" => PortType::Number,
        "boolean" => PortType::Boolean,
        "object" => PortType::Object,
        "array" => PortType::Array,
        "binary" => PortType::Binary,
        _ => PortType::Any,
    }
}

/// Node types that act as HTTP/unix triggers for a deployed flow.
pub const HOOK_NODE_TYPES: [&str; 4] = ["http-in", "unix-in", "webhook", "webhook-trigger"];

/// Normalizes a configured hook path to the sub-path form used for matching:
/// empty or `"/"` becomes `"/"`, otherwise a single leading slash is ensured.
pub fn normalize_hook_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    }
}

/// Restricts a compiled flow to the nodes reachable from `trigger`.
///
/// A canvas can contain several triggers with different auth policies; an
/// executed request must only touch the branch of the matched trigger.
pub fn restrict_to_trigger(flow: &mut Flow, trigger: Uuid) {
    let mut keep = std::collections::HashSet::from([trigger]);
    let mut queue = std::collections::VecDeque::from([trigger]);
    while let Some(node) = queue.pop_front() {
        for edge in flow.edges.iter().filter(|e| e.from_node == node) {
            if keep.insert(edge.to_node) {
                queue.push_back(edge.to_node);
            }
        }
    }
    flow.nodes.retain(|n| keep.contains(&n.id));
    flow.edges
        .retain(|e| keep.contains(&e.from_node) && keep.contains(&e.to_node));
}

/// Builds the trigger payload exactly as the HTTP hook handler does:
/// `{ method, path, headers, query, body }`.
pub fn hook_trigger_payload(
    method: impl Into<String>,
    path: impl Into<String>,
    headers: serde_json::Value,
    query: serde_json::Value,
    body: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "method": method.into(),
        "path": path.into(),
        "headers": headers,
        "query": query,
        "body": body,
    })
}

/// Builds the trigger [`FlowMessage`] for a hook call. The source node is the
/// nil UUID and the port is `"hook"`, identical to the HTTP hook handler.
pub fn hook_trigger_message(payload: serde_json::Value, trace_id: Uuid) -> FlowMessage {
    FlowMessage::new(Uuid::nil(), "hook", payload, trace_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Flow;

    fn canvas_flow() -> Flow {
        let mut flow = Flow::new("canvas");
        let nodes = serde_json::json!([
            {
                "id": "n1",
                "data": {
                    "type": "http-in",
                    "label": "In",
                    "config": {"path": "/x"},
                    "inputs": [],
                    "outputs": [{"id": "output", "type": "object"}]
                }
            },
            {
                "id": "n2",
                "data": {
                    "type": "debug",
                    "label": "Dbg",
                    "inputs": [{"id": "input", "type": "any"}],
                    "outputs": [{"id": "output", "type": "any"}]
                }
            }
        ]);
        let edges = serde_json::json!([
            {"source": "n1", "sourceHandle": "output", "target": "n2", "targetHandle": "input"}
        ]);
        flow.metadata.positions.insert("canvas_nodes".into(), nodes);
        flow.metadata.positions.insert("canvas_edges".into(), edges);
        flow
    }

    #[test]
    fn compiles_nodes_and_edges() {
        let (flow, id_map) = canvas_to_flow(&canvas_flow()).unwrap();
        assert_eq!(flow.nodes.len(), 2);
        assert_eq!(flow.edges.len(), 1);
        assert!(id_map.contains_key("n1"));
        assert_eq!(flow.nodes[0].config["path"], "/x");
    }

    #[test]
    fn deterministic_ids() {
        let f = canvas_flow();
        let (a, _) = canvas_to_flow(&f).unwrap();
        let (b, _) = canvas_to_flow(&f).unwrap();
        assert_eq!(a.nodes[0].id, b.nodes[0].id);
    }

    #[test]
    fn missing_canvas_is_an_error() {
        let flow = Flow::new("empty");
        assert!(matches!(
            canvas_to_flow(&flow),
            Err(CanvasError::NoCanvasNodes)
        ));
    }

    #[test]
    fn hook_payload_shape() {
        let payload = hook_trigger_payload(
            "POST",
            "/x",
            serde_json::json!({"a": "b"}),
            serde_json::json!({}),
            serde_json::json!({"k": 1}),
        );
        assert_eq!(payload["method"], "POST");
        assert_eq!(payload["path"], "/x");
        assert_eq!(payload["body"]["k"], 1);
        let msg = hook_trigger_message(payload, Uuid::nil());
        assert_eq!(msg.source_port, "hook");
    }
}
