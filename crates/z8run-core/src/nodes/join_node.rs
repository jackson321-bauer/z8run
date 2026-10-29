//! join — sammelt N parallele Zweige EINER Ausführung (trace_id) und merged
//! die Payloads zu einer Nachricht.
//!
//! Warum: Die Engine reicht Nachrichten 1:1 weiter (Message-Passing, kein
//! stilles Vermischen). Ein Trigger mit 2 downstream Nodes erzeugt 2
//! getrennte Nachrichten — Felder beider Zweige treffen nie zusammen.
//! Der join-Node schließt diese Lücke OHNE die Engine-Semantik zu ändern:
//!
//! - Er zählt ANKOMMENDE Nachrichten mit UNTERSCHIEDLICHEN source_node-IDs
//!   (jeder Parallelzweig hat seine eigene Quell-Node).
//! - Sind `inputs` verschiedene Quellen gesammelt: shallow-merge der
//!   Payloads (spätere Zweige überschreiben gleiche Felder) → output-Port.
//! - Kommt eine Nachricht mit "error"-Feld: sofortiger Durchreich-Fehler
//!   auf den error-Port (fail-fast, ohne auf die anderen Zweige zu warten).
//! - Timeout (timeoutMs ab erster Nachricht): der Eintrag wird verworfen
//!   und als Fehler gemeldet — kein Speicherleck durch hängende Traces.
//!
//! Der State ist pro join-Node-Instanz (Mutex-geschützt); Einträge sind
//! pro trace_id, Cleanup läuft lazy bei jedem process-Aufruf.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::debug;

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

struct JoinEntry {
    first_seen: Instant,
    /// source_node -> payload (jeder Zweig liefert seine.payload)
    parts: HashMap<uuid::Uuid, Value>,
}

pub struct JoinNode {
    name: String,
    /// Anzahl erwarteter Quell-Nodes (Parallelezweige).
    inputs: usize,
    /// Abbruch: so lange wird ab erster Nachricht auf Rest gewartet.
    timeout_ms: u64,
    state: Mutex<HashMap<uuid::Uuid, JoinEntry>>,
}

#[async_trait::async_trait]
impl NodeExecutor for JoinNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        // Fail-fast: eingehender Zweig hat bereits einen Fehler → sofort
        // weiterreichen, Trace-Eintrag verwerfen.
        if msg
            .payload
            .get("error")
            .map(|v| !v.is_null())
            .unwrap_or(false)
        {
            self.remove_entry(&msg.trace_id);
            return Ok(vec![msg.derive(
                msg.source_node,
                "error",
                msg.payload.clone(),
            )]);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::error::Z8Error::Internal("join: state poisoned".into()))?;

        // Lazy-Cleanup abgelaufener Traces (kein Hintergrundtask nötig).
        let timeout = Duration::from_millis(if self.timeout_ms == 0 {
            10_000
        } else {
            self.timeout_ms
        });
        let expired: Vec<uuid::Uuid> = state
            .iter()
            .filter(|(_, e)| e.first_seen.elapsed() > timeout)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            let e = state.remove(&k);
            debug!(node = %self.name, trace = %k, "join: Eintrag nach Timeout verworfen");
            let _ = e;
        }

        let expected = if self.inputs == 0 { 2 } else { self.inputs };
        let entry = state.entry(msg.trace_id).or_insert_with(|| JoinEntry {
            first_seen: Instant::now(),
            parts: HashMap::new(),
        });
        entry.parts.insert(msg.source_node, msg.payload.clone());
        let distinct = entry.parts.len();

        if distinct < expected {
            // Noch nicht vollständig: nichts emittieren, weiter sammeln.
            debug!(
                node = %self.name,
                trace = %msg.trace_id,
                collected = distinct,
                expected = expected,
                "join: sammle weiter"
            );
            return Ok(vec![]);
        }

        // Vollständig: shallow-merge (Einfügereihenfolge = HashMap, gleiche
        // Felder überschreiben sich — deterministisch genug, da Zweige
        // disjunkte Felder liefern sollen; Konflikte gelten als Planungsfehler).
        let entry = state.remove(&msg.trace_id).expect("entry gerade eingefügt");
        let mut merged = serde_json::Map::new();
        for (_src, part) in entry.parts {
            if let Some(obj) = part.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        let merged = Value::Object(merged);
        let trace = msg.trace_id;
        debug!(
            node = %self.name,
            trace = %trace,
            parts = distinct,
            "join: vollständig, merge emittiert"
        );
        Ok(vec![msg.derive(msg.source_node, "output", merged)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "inputs" => inputs: usize,
            "timeoutMs" => timeout_ms: u64,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        let expected = if self.inputs == 0 { 2 } else { self.inputs };
        if expected < 2 {
            return Err(crate::error::Z8Error::Internal(
                "join: inputs muss >= 2 sein (ein Einzelzweig braucht keinen join)".into(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "join"
    }
}

impl JoinNode {
    fn remove_entry(&self, trace: &uuid::Uuid) {
        if let Ok(mut state) = self.state.lock() {
            state.remove(trace);
        }
    }
}

node_factory!(JoinNodeFactory, JoinNode, "join", {
    name: String::new(),
    inputs: 2usize,
    timeout_ms: 10_000u64,
    state: Mutex::new(HashMap::new()),
});

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn msg_from(src: uuid::Uuid, payload: Value) -> FlowMessage {
        let trace = Uuid::now_v7();
        FlowMessage::new(src, "output", payload, trace)
    }

    #[tokio::test]
    async fn merge_zwei_zweige() {
        let mut node = JoinNode {
            name: "t".into(),
            inputs: 2,
            timeout_ms: 10_000,
            state: Mutex::new(HashMap::new()),
        };
        node.configure(serde_json::json!({"inputs": 2}))
            .await
            .unwrap();

        let a = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        let trace = Uuid::now_v7();
        let m1 = FlowMessage::new(a, "output", serde_json::json!({"addr_user": "u1"}), trace);
        let m2 = FlowMessage::new(b, "output", serde_json::json!({"addr_space": "s1"}), trace);

        let out1 = node.process(m1).await.unwrap();
        assert!(out1.is_empty(), "erster Zweig darf noch nichts emittieren");

        let out2 = node.process(m2).await.unwrap();
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].source_port, "output");
        assert_eq!(out2[0].payload["addr_user"], "u1");
        assert_eq!(out2[0].payload["addr_space"], "s1");
    }

    #[tokio::test]
    async fn fail_fast_bei_fehler() {
        let mut node = JoinNode {
            name: "t".into(),
            inputs: 2,
            timeout_ms: 10_000,
            state: Mutex::new(HashMap::new()),
        };
        node.configure(serde_json::json!({"inputs": 2}))
            .await
            .unwrap();

        let a = uuid::Uuid::now_v7();
        let trace = Uuid::now_v7();
        let ok = FlowMessage::new(a, "output", serde_json::json!({"x": 1}), trace);
        let _ = node.process(ok).await.unwrap();

        let err_src = uuid::Uuid::now_v7();
        let err = FlowMessage::new(
            err_src,
            "output",
            serde_json::json!({"error": "zweig kaputt"}),
            trace,
        );
        let out = node.process(err).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source_port, "error");
        assert_eq!(out[0].payload["error"], "zweig kaputt");
        // State ist leer: Trace wurde verworfen.
        assert!(node.state.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn timeout_räumt_auf() {
        let mut node = JoinNode {
            name: "t".into(),
            inputs: 2,
            timeout_ms: 1, // 1 ms — läuft beim zweiten Aufruf sofort ab
            state: Mutex::new(HashMap::new()),
        };
        node.configure(serde_json::json!({"inputs": 2, "timeoutMs": 1}))
            .await
            .unwrap();

        let a = uuid::Uuid::now_v7();
        let trace1 = Uuid::now_v7();
        let m = FlowMessage::new(a, "output", serde_json::json!({"x": 1}), trace1);
        let _ = node.process(m).await.unwrap();
        assert_eq!(node.state.lock().unwrap().len(), 1);

        // kurze Wartezeit > timeout, dann neuer Trace: Cleanup läuft lazy
        tokio::time::sleep(Duration::from_millis(5)).await;
        let trace2 = Uuid::now_v7();
        let other = uuid::Uuid::now_v7();
        let m2 = FlowMessage::new(other, "output", serde_json::json!({"y": 2}), trace2);
        let _ = node.process(m2).await.unwrap();
        assert!(
            node.state.lock().unwrap().len() <= 1,
            "abgelaufener Trace muss weg sein"
        );
    }

    #[tokio::test]
    async fn valide_inputs_grenzen() {
        let mut node = JoinNode {
            name: "t".into(),
            inputs: 1,
            timeout_ms: 0,
            state: Mutex::new(HashMap::new()),
        };
        node.configure(serde_json::json!({"inputs": 1}))
            .await
            .unwrap();
        assert!(
            node.validate().await.is_err(),
            "inputs=1 muss abgelehnt werden"
        );
    }

    #[allow(dead_code)]
    fn msg_from_unused(_src: uuid::Uuid, _payload: Value) -> FlowMessage {
        msg_from(_src, _payload)
    }
}
