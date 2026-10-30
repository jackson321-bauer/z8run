//! S4: LineFS-/Ordner-Nodes im echten Flow (open/write/close/list).

mod common;

use common::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::engine::{EngineEvent, FlowEngine, NodeExecutor, NodeExecutorFactory};
use z8run_core::flow::Flow;
use z8run_core::message::FlowMessage;
use z8run_core::node::{Node, PortType};
use z8run_core::nodes::dbnode_common::engine;
use z8run_core::nodes::register_builtin_nodes;

struct CaptureNode(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl NodeExecutor for CaptureNode {
    async fn process(&self, msg: FlowMessage) -> z8run_core::Z8Result<Vec<FlowMessage>> {
        self.0.lock().unwrap().push(msg.payload.clone());
        Ok(vec![])
    }
    async fn configure(&mut self, _c: Value) -> z8run_core::Z8Result<()> { Ok(()) }
    async fn validate(&self) -> z8run_core::Z8Result<()> { Ok(()) }
    fn node_type(&self) -> &str { "test-capture" }
}

struct CaptureFactory(Arc<Mutex<Vec<Value>>>);
#[async_trait::async_trait]
impl NodeExecutorFactory for CaptureFactory {
    async fn create(&self, _c: Value) -> z8run_core::Z8Result<Box<dyn NodeExecutor>> {
        Ok(Box::new(CaptureNode(self.0.clone())))
    }
    fn node_type(&self) -> &str { "test-capture" }
}

fn b64_master() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(master())
}

#[tokio::test]
async fn linefs_nodes_open_write_close_list() {
    let base = temp_base("linefs-s4-nodes");
    // Vorbedingung: Datei direkt in der globalen Engine anlegen.
    let eng = engine();
    eng.open_db("lf", &master(), cluster("lf", &base)).await.unwrap();
    eng.reserve("lf", "pre").unwrap();
    eng.linefs(LinefsRequest {
        db_id: "lf".into(), session_id: "pre".into(),
        aktion: LinefsAktion::LinefsAnlegen {
            name: "demo.txt".into(), art: "code".into(), text: "alt\nzeile2".into(),
            urheber: "ki".into(), ordner_id: None,
        },
    }).await.unwrap();
    eng.release("lf", "pre").unwrap();

    let fe = FlowEngine::new();
    register_builtin_nodes(&fe).await;
    let slot = Arc::new(Mutex::new(Vec::new()));
    fe.register_node_type(Arc::new(CaptureFactory(slot.clone()))).await;

    let mut flow = Flow::new("linefs-nodes");
    let mk = |id: &str, typ: &str, cfg: Value| Node::new(id, typ)
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(cfg);
    let trig = Node::new("in", "unix-in").with_output("output", PortType::Object)
        .with_config(json!({"method": "POST", "path": "/linefs"}));
    let open = mk("open", "db-open", json!({
        "dbId": "lf", "clusterId": "lf", "adapter": "fs",
        "localDir": base.to_string_lossy(), "storageRoot": base.join("storage").to_string_lossy(),
        "masterKeyPath": "req.body.master_key_b64"
    }));
    let lopen = mk("lopen", "linefs-open", json!({
        "dbId": "lf", "pfadPath": "req.body.pfad",
        "sessionPath": "req.body.session_id", "autoReserve": true
    }));
    let write = mk("write", "linefs-write", json!({
        "dbId": "lf", "sessionPath": "req.body.session_id", "modus": "setzen",
        "nrPath": "req.body.nr", "inhaltPath": "req.body.inhalt", "autoReserve": true
    }));
    let close = mk("close", "linefs-close", json!({
        "dbId": "lf", "sessionPath": "req.body.session_id", "autoReserve": true
    }));
    let list = mk("list", "linefs-list", json!({"dbId": "lf", "elternId": 0}));
    let cap = Node::new("cap", "test-capture").with_input("input", PortType::Any);
    let (t, o, lo, w, c, l, cp) = (trig.id, open.id, lopen.id, write.id, close.id, list.id, cap.id);
    for n in [trig, open, lopen, write, close, list, cap] { flow.add_node(n); }
    flow.connect(t, "output", o, "input").unwrap();
    flow.connect(o, "output", lo, "input").unwrap();
    flow.connect(lo, "output", w, "input").unwrap();
    flow.connect(w, "output", c, "input").unwrap();
    flow.connect(c, "output", l, "input").unwrap();
    flow.connect(l, "output", cp, "input").unwrap();
    for (id, handle) in [(o, "error"), (lo, "error"), (w, "error"), (c, "error"), (l, "error")] {
        flow.connect(id, handle, cp, "input").unwrap();
    }

    let mut ev = fe.subscribe_events();
    let payload = json!({"req": {"method": "POST", "path": "/linefs", "body": {
        "master_key_b64": b64_master(), "session_id": "s", "pfad": "demo.txt",
        "nr": 1, "inhalt": "NEU"
    }}});
    let msg = FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7());
    let trace = fe.execute_with_trigger(flow, Some(msg)).await.unwrap();
    loop {
        let e = tokio::time::timeout(Duration::from_secs(10), ev.recv())
            .await.expect("Flow-Timeout").expect("Event");
        match e {
            EngineEvent::FlowCompleted { trace_id, .. } if trace_id == trace => break,
            EngineEvent::FlowError { trace_id, error, .. } if trace_id == trace => panic!("{error}"),
            _ => {}
        }
    }
    let out = slot.lock().unwrap().clone();
    let tree = out.iter().find(|p| p.get("eintraege").is_some()).expect("Baum fehlt");
    let eintraege = tree["eintraege"].as_array().unwrap();
    assert!(eintraege.iter().any(|e| e["name"] == "demo.txt"), "{tree:?}");
    assert!(tree.pointer("/req/body/master_key_b64").is_none(), "Masterkey im Output");
    let r = eng.linefs(LinefsRequest {
        db_id: "lf".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsRendere { pfad: "demo.txt".into() },
    }).await.unwrap();
    assert_eq!(r["text"], "NEU\nzeile2");
}
