//! S2: dünne Z8-Nodes im echten Flow — blob-put (Datei) -> blob-get -> sha256
//! gleich; blob-get fremde db_id = error-Port; blob-delete ohne Reservierung
//! = error-Port (Ein-Schreiber greift auch für Meta-Zeilen).

mod common;

use common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
        Ok(Box::new(CaptureNode { slot: self.0.clone() }))
    }
    fn node_type(&self) -> &str {
        "test-capture"
    }
}

fn b64_master() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(master())
}

async fn run_flow(engine: &FlowEngine, flow: Flow, payload: Value) -> Arc<Mutex<Vec<Value>>> {
    let mut ev = engine.subscribe_events();
    let msg = FlowMessage::new(Uuid::now_v7(), "output", payload, Uuid::now_v7());
    let trace = engine.execute_with_trigger(flow, Some(msg)).await.unwrap();
    loop {
        let e = tokio::time::timeout(Duration::from_secs(15), ev.recv())
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
    engine_events_placeholder()
}

fn engine_events_placeholder() -> Arc<Mutex<Vec<Value>>> {
    Arc::new(Mutex::new(Vec::new()))
}

fn trigger(path: &str) -> Node {
    Node::new("in", "unix-in")
        .with_output("output", PortType::Object)
        .with_config(json!({"method": "POST", "path": path}))
}

fn db_open(base: &std::path::Path, db: &str) -> Node {
    Node::new("open", "db-open")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({
            "dbId": db, "clusterId": "c1", "adapter": "fs",
            "localDir": base.to_string_lossy(),
            "storageRoot": base.join("storage").to_string_lossy(),
            "masterKeyPath": "req.body.master_key_b64"
        }))
}

#[tokio::test]
async fn s2_put_get_roundtrip_und_fehlerports() {
    let base = temp_base("blob-s2");
    std::fs::create_dir_all(&base).unwrap();
    let quelle = base.join("quelle.bin");
    let inhalt = b"FLOW-BLOB-ROUNDTRIP-2026".to_vec();
    std::fs::write(&quelle, &inhalt).unwrap();
    let ziel = base.join("ziel.bin");

    let engine = FlowEngine::new();
    register_builtin_nodes(&engine).await;
    let slot = Arc::new(Mutex::new(Vec::new()));
    engine
        .register_node_type(Arc::new(CaptureFactory(slot.clone()))
            as Arc<dyn NodeExecutorFactory>)
        .await;

    // 1) put (Datei) -> get (Datei-Ziel) -> capture
    let mut f = Flow::new("blob-putget");
    let trig1 = trigger("/blobput");
    let open1 = db_open(&base, "db-s2");
    let put = Node::new("put", "blob-put")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({"dbId": "db-s2", "pfadPath": "req.body.datei_pfad",
            "sessionPath": "req.body.session_id", "autoReserve": true}));
    let get = Node::new("get", "blob-get")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({"dbId": "db-s2", "blobIdPath": "blob.blob_id",
            "zielPath": "req.body.ziel_adapter"}));
    let cap = Node::new("cap", "test-capture").with_input("input", PortType::Any);
    let (t, o, p, g, c) = (trig1.id, open1.id, put.id, get.id, cap.id);
    for n in [trig1, open1, put, get, cap] {
        f.add_node(n);
    }
    f.connect(t, "output", o, "input").unwrap();
    f.connect(o, "output", p, "input").unwrap();
    f.connect(p, "output", g, "input").unwrap();
    f.connect(g, "output", c, "input").unwrap();
    f.connect(g, "error", c, "input").unwrap();
    f.connect(p, "error", c, "input").unwrap();
    f.connect(o, "error", c, "input").unwrap();

    let payload = json!({"req": {"method": "POST", "path": "/blobput", "body": {
        "master_key_b64": b64_master(), "session_id": "flow-s2", "db_id": "db-s2",
        "datei_pfad": quelle.to_string_lossy(), "name": "quelle.bin",
        "mime": "application/octet-stream",
        "ziel_adapter": ziel.to_string_lossy()
    }}});
    run_flow(&engine, f, payload).await;
    let out = slot.lock().unwrap().clone();
    assert!(out.iter().any(|v| v["status"] == 200 && v["ziel"].is_string()), "get-Output fehlt");
    let a = Sha256::digest(std::fs::read(&quelle).unwrap());
    let b = Sha256::digest(std::fs::read(&ziel).unwrap());
    assert_eq!(hex::encode(a), hex::encode(b), "flow sha256 != original");

    // 2) blob-get fremde (nicht offene) db_id = error-Port
    let mut f2 = Flow::new("blob-fremd");
    let trig2 = trigger("/blobfremd");
    let g2 = Node::new("get2", "blob-get")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({"dbId": "db-fremd", "blobIdPath": "req.body.blob_id"}));
    let c2 = Node::new("cap2", "test-capture").with_input("input", PortType::Any);
    let (t2i, g2i, c2i) = (trig2.id, g2.id, c2.id);
    for n in [trig2, g2, c2] {
        f2.add_node(n);
    }
    f2.connect(t2i, "output", g2i, "input").unwrap();
    f2.connect(g2i, "output", c2i, "input").unwrap();
    f2.connect(g2i, "error", c2i, "input").unwrap();
    run_flow(&engine, f2, json!({"req": {"method": "POST", "path": "/blobfremd",
        "body": {"blob_id": "egal"}}})).await;
    assert!(slot.lock().unwrap().iter().any(|v| v["code"] == "NOT_OPEN"), "kein NOT_OPEN");

    // 3) blob-delete ohne Reservierung = error-Port
    let mut f3 = Flow::new("blob-delete-nores");
    let trig3 = trigger("/blobdel");
    let o3 = db_open(&base, "db-s2");
    let p3 = Node::new("put3", "blob-put")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({"dbId": "db-s2", "base64Path": "req.body.base64",
            "sessionPath": "req.body.session_id", "autoReserve": true}));
    let d3 = Node::new("del3", "blob-delete")
        .with_input("input", PortType::Any)
        .with_output("output", PortType::Object)
        .with_output("error", PortType::Any)
        .with_config(json!({"dbId": "db-s2", "blobIdPath": "blob.blob_id",
            "sessionPath": "req.body.session_id", "autoReserve": false}));
    let c3 = Node::new("cap3", "test-capture").with_input("input", PortType::Any);
    let (t3i, o3i, p3i, d3i, c3i) = (trig3.id, o3.id, p3.id, d3.id, c3.id);
    for n in [trig3, o3, p3, d3, c3] {
        f3.add_node(n);
    }
    f3.connect(t3i, "output", o3i, "input").unwrap();
    f3.connect(o3i, "output", p3i, "input").unwrap();
    f3.connect(p3i, "output", d3i, "input").unwrap();
    f3.connect(d3i, "output", c3i, "input").unwrap();
    f3.connect(d3i, "error", c3i, "input").unwrap();
    f3.connect(p3i, "error", c3i, "input").unwrap();
    run_flow(&engine, f3, json!({"req": {"method": "POST", "path": "/blobdel", "body": {
        "master_key_b64": b64_master(), "session_id": "flow-del", "db_id": "db-s2",
        "base64": "ZGVsZXRlLW9obmUtcmVzZXJ2aWVydW5n"
    }}})).await;
    assert!(slot.lock().unwrap().iter().any(|v| v["code"] == "NOT_RESERVED"), "kein NOT_RESERVED");
}
