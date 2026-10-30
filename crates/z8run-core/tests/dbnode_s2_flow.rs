//! S2: dünne Z8-Nodes im echten Flow (unix-in POST /dbschema), Schema-Felder,
//! db-write happy/Negativ (error-Port) und paralleles Lesen.

mod common;

use common::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;
use z8run_core::engine::{EngineEvent, FlowEngine, NodeExecutor, NodeExecutorFactory};
use z8run_core::flow::Flow;
use z8run_core::message::FlowMessage;
use z8run_core::node::{Node, PortType};
use z8run_core::nodes::register_builtin_nodes;

struct CaptureNode {
    slot: Arc<Mutex<Vec<Value>>>,
}

#[async_trait::async_trait]
impl NodeExecutor for CaptureNode {
    async fn process(&self, msg: FlowMessage) -> z8run_core::Z8Result<Vec<FlowMessage>> {
        self.slot.lock().unwrap().push(msg.payload.clone());
        Ok(vec![])
    }
    async fn configure(&mut self, _c: Value) -> z8run_core::Z8Result<()> {
        Ok(())
    }
    async fn validate(&self) -> z8run_core::Z8Result<()> {
        Ok(())
    }
    fn node_type(&self) -> &str {
        "test-capture"
    }
}

struct CaptureFactory(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl NodeExecutorFactory for CaptureFactory {
    async fn create(&self, _c: Value) -> z8run_core::Z8Result<Box<dyn NodeExecutor>> {
        Ok(Box::new(CaptureNode {
            slot: self.0.clone(),
        }))
    }
    fn node_type(&self) -> &str {
        "test-capture"
    }
}

fn b64_master() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(master())
}

fn build_flow(base: &std::path::Path, db: &str, auto: bool) -> (Flow, Arc<Mutex<Vec<Value>>>) {
    let slot = Arc::new(Mutex::new(Vec::new()));
    let mut f = Flow::new("db-flow");
    let trig = Node::new("in", "unix-in")
        .with_output("output", PortType::Object)
        .with_config(json!({"method": "POST", "path": "/dbschema"}));
    let open = Node::new("open", "db-open")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({
            "dbId": db, "clusterId": "c1", "adapter": "fs",
            "localDir": base.to_string_lossy(), "storageRoot": base.join("storage").to_string_lossy(),
            "masterKeyPath": "req.body.master_key_b64"
        }));
    let write = Node::new("write", "db-write")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({
            "dbId": db, "sql": "CREATE TABLE t (x INTEGER)",
            "sessionPath": "req.body.session_id", "autoReserve": auto
        }));
    let schema = Node::new("schema", "db-schema")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({"dbId": db}));
    let cap = Node::new("cap", "test-capture").with_input("input", PortType::Any);
    let (t, o, w, s, c) = (trig.id, open.id, write.id, schema.id, cap.id);
    f.add_node(trig);
    f.add_node(open);
    f.add_node(write);
    f.add_node(schema);
    f.add_node(cap);
    f.connect(t, "output", o, "input").unwrap();
    f.connect(o, "output", w, "input").unwrap();
    f.connect(w, "output", s, "input").unwrap();
    f.connect(s, "output", c, "input").unwrap();
    f.connect(w, "error", c, "input").unwrap();
    (f, slot)
}

async fn run(engine: &FlowEngine, flow: Flow, db: &str, session: &str) {
    let mut ev = engine.subscribe_events();
    let payload = json!({"req": {"method": "POST", "path": "/dbschema",
        "body": {"master_key_b64": b64_master(), "session_id": session, "db": db}}});
    let msg = FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7());
    let trace = engine.execute_with_trigger(flow, Some(msg)).await.unwrap();
    loop {
        let e = tokio::time::timeout(Duration::from_secs(10), ev.recv())
            .await
            .expect("Flow-Timeout")
            .expect("Event-Kanal");
        match e {
            EngineEvent::FlowCompleted { trace_id, .. } if trace_id == trace => break,
            EngineEvent::FlowError { trace_id, error, .. } if trace_id == trace => {
                panic!("FlowError: {error}")
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn flow_unix_in_db_open_schema_mit_schema_feldern() {
    let base = temp_base("s2-flow");
    let engine = FlowEngine::new();
    register_builtin_nodes(&engine).await;
    let slot = Arc::new(Mutex::new(Vec::new()));
    engine
        .register_node_type(Arc::new(CaptureFactory(slot.clone())))
        .await;
    let (flow, _) = build_flow(&base, "db-flow", true);
    run(&engine, flow, "db-flow", "s").await;
    let payloads = slot.lock().unwrap().clone();
    assert!(!payloads.is_empty(), "kein Schema-Output");
    let schema = payloads
        .iter()
        .find(|p| p.get("tabellen").is_some())
        .expect("tabellen fehlt");
    assert!(schema.pointer("/req/body/master_key_b64").is_none(), "Masterkey im Output!");
    let t = &schema["tabellen"][0];
    assert_eq!(t["name"], "t");
    assert_eq!(t["spalten"][0]["name"], "x");
    assert_eq!(t["spalten"][0]["typ"], "INTEGER");
    assert_eq!(t["zeilen"], 0);
    assert!(t["wal_stand"].as_u64().unwrap() >= 1);
    assert!(t["reserviert_von"].is_null());
}

#[tokio::test]
async fn db_write_ohne_reservierung_geht_auf_error_port() {
    let base = temp_base("s2-neg");
    let engine = FlowEngine::new();
    register_builtin_nodes(&engine).await;
    let slot = Arc::new(Mutex::new(Vec::new()));
    engine
        .register_node_type(Arc::new(CaptureFactory(slot.clone())))
        .await;
    let (flow, _) = build_flow(&base, "db-neg", false);
    // open zuerst ohne write (Reservierung fehlt bewusst)
    run(&engine, flow, "db-neg", "").await;
    let payloads = slot.lock().unwrap().clone();
    let err = payloads
        .iter()
        .find(|p| p.get("code").is_some())
        .expect("kein Error-Output");
    assert_eq!(err["code"], "NOT_RESERVED");
}
