//! S3: DB-Schema-Canvas-Beweis — EIN Flow mit 5 db-open + 5 db-schema,
//! Antwort-JSON landet als Rohlog. (Canvas zeigt 5 verbundene DBs.)

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

struct Cap(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl NodeExecutor for Cap {
    async fn process(&self, m: FlowMessage) -> z8run_core::Z8Result<Vec<FlowMessage>> {
        self.0.lock().unwrap().push(m.payload.clone());
        Ok(vec![])
    }
    async fn configure(&mut self, _c: Value) -> z8run_core::Z8Result<()> {
        Ok(())
    }
    async fn validate(&self) -> z8run_core::Z8Result<()> {
        Ok(())
    }
    fn node_type(&self) -> &str {
        "cap5"
    }
}

struct CapF(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl NodeExecutorFactory for CapF {
    async fn create(&self, _c: Value) -> z8run_core::Z8Result<Box<dyn NodeExecutor>> {
        Ok(Box::new(Cap(self.0.clone())))
    }
    fn node_type(&self) -> &str {
        "cap5"
    }
}

#[tokio::test]
async fn flow_antwortet_schema_fuer_fuenf_verbundene_dbs() {
    use base64::Engine;
    let base = temp_base("s3-schema5");
    let master = base64::engine::general_purpose::STANDARD.encode(master());
    let engine = FlowEngine::new();
    register_builtin_nodes(&engine).await;
    let slot = Arc::new(Mutex::new(Vec::new()));
    engine.register_node_type(Arc::new(CapF(slot.clone()))).await;

    let mut f = Flow::new("db-schema-5");
    let trig = Node::new("in", "unix-in")
        .with_output("output", PortType::Object)
        .with_config(json!({"method": "POST", "path": "/dbschema"}));
    let t = trig.id;
    f.add_node(trig);
    let cap = Node::new("cap", "cap5").with_input("input", PortType::Any);
    let cap_id = cap.id;
    f.add_node(cap);
    for i in 0..5 {
        let db = format!("db5-{i}");
        let open = Node::new(format!("open-{i}"), "db-open")
            .with_input("input", PortType::Any)
            .with_output("output", PortType::Object)
            .with_config(json!({
                "dbId": db, "clusterId": "c1", "adapter": "fs",
                "localDir": base.to_string_lossy(),
                "storageRoot": base.join("storage").to_string_lossy(),
                "masterKeyPath": "req.body.master_key_b64"
            }));
        let write = Node::new(format!("write-{i}"), "db-write")
            .with_input("input", PortType::Any)
            .with_output("output", PortType::Object)
            .with_config(json!({"dbId": db, "sql": "CREATE TABLE t (x INTEGER)",
                                "sessionPath": "req.body.session_id", "autoReserve": true}));
        let schema = Node::new(format!("schema-{i}"), "db-schema")
            .with_input("input", PortType::Any)
            .with_output("output", PortType::Object)
            .with_config(json!({"dbId": db}));
        let (o, w, s) = (open.id, write.id, schema.id);
        f.add_node(open);
        f.add_node(write);
        f.add_node(schema);
        f.connect(t, "output", o, "input").unwrap();
        f.connect(o, "output", w, "input").unwrap();
        f.connect(w, "output", s, "input").unwrap();
        f.connect(s, "output", cap_id, "input").unwrap();
    }

    let mut ev = engine.subscribe_events();
    let payload = json!({"req": {"method": "POST", "path": "/dbschema",
        "body": {"master_key_b64": master, "session_id": "s"}}});
    let msg = FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7());
    let trace = engine.execute_with_trigger(f, Some(msg)).await.unwrap();
    loop {
        let e = tokio::time::timeout(Duration::from_secs(15), ev.recv())
            .await
            .expect("Timeout")
            .expect("Kanal");
        match e {
            EngineEvent::FlowCompleted { trace_id, .. } if trace_id == trace => break,
            EngineEvent::FlowError { error, .. } => panic!("FlowError: {error}"),
            _ => {}
        }
    }
    let out = slot.lock().unwrap().clone();
    let mut dbs: Vec<String> = out
        .iter()
        .filter_map(|p| p.get("db_id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    dbs.sort();
    dbs.dedup();
    assert_eq!(dbs.len(), 5, "nicht 5 DBs: {dbs:?}");
    for p in &out {
        if let Some(tabb) = p.get("tabellen").and_then(|v| v.as_array()) {
            assert_eq!(tabb[0]["name"], "t");
            assert_eq!(tabb[0]["spalten"][0]["name"], "x");
        }
    }
    println!("SCHEMA-5-ANTWORT {}", serde_json::to_string(&out).unwrap());
}
