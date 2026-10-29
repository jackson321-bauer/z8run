
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
