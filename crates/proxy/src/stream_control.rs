//! Control-Frame-Behandlung (JSON). Nur hier wird JSON gelesen — der
//! Medienpfad (Binaer) bleibt uninterpretiert.

use std::sync::Arc;

use axum::extract::ws::Message;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::channel::ChannelRegistry;
use crate::service::ProxyService;
use crate::stream::Setup;
use crate::stream_conn::{send_err, send_json, spawn_forward};

#[allow(clippy::too_many_arguments)]
pub async fn handle_control(
    svc: &Arc<ProxyService>,
    reg: &Arc<ChannelRegistry>,
    writable: &mut std::collections::HashSet<String>,
    joined: &mut Vec<String>,
    tx: &mpsc::Sender<Message>,
    setup: &Setup,
    sid: u64,
    v: &Value,
) {
    match v.get("type").and_then(Value::as_str).unwrap_or("") {
        "heartbeat" => {
            let _ = send_json(tx, json!({"type": "heartbeat", "ts_ms": now_ms()})).await;
        }
        "subscribe" => {
            let ch = v.get("channel").and_then(Value::as_str).unwrap_or("");
            match reg.subscribe(ch, sid) {
                Ok(sub) => {
                    joined.push(ch.to_string());
                    tokio::spawn(spawn_forward(reg.clone(), sub, tx.clone()));
                    let _ = send_json(tx, json!({"type": "ack", "subscribed": ch})).await;
                }
                Err(e) => send_err(tx, e.code(), &e.to_string()).await,
            }
        }
        "claim" => {
            let ch = v.get("channel").and_then(Value::as_str).unwrap_or("");
            // G3: Identitaet ist die Session, nicht ein Client-Feld.
            let identity = setup.identity.as_str();
            match reg.claim(ch, identity, sid) {
                Ok(g) => {
                    writable.insert(ch.to_string());
                    if !joined.contains(&ch.to_string()) {
                        joined.push(ch.to_string());
                    }
                    let _ = send_json(
                        tx,
                        json!({"type": "ack", "claimed": ch, "stream_id": g.stream_id}),
                    )
                    .await;
                }
                Err(e) => send_err(tx, e.code(), &e.to_string()).await,
            }
        }
        "release" => {
            let ch = v.get("channel").and_then(Value::as_str).unwrap_or("");
            match reg.release(ch, &setup.identity) {
                Ok(()) => {
                    writable.remove(ch);
                    let _ = send_json(tx, json!({"type": "ack", "released": ch})).await;
                }
                Err(e) => send_err(tx, e.code(), &e.to_string()).await,
            }
        }
        // G17: Rotation lebt im Socket weiter — neues Token wird geprueft,
        // die Verbindung bleibt bestehen (gleiche Session-Identitaet).
        "token" => {
            let tok = v.get("token").and_then(Value::as_str).unwrap_or("");
            match svc.authenticate(tok) {
                Ok(info) if info.session_id == setup.session_id => {
                    svc.record_meta(
                        "app",
                        proxy_kern::meta::EventKind::AppCall,
                        "stream",
                        "",
                        &setup.session_id,
                        "ok",
                        "token_rotated",
                    )
                    .await;
                    let _ = send_json(tx, json!({"type": "ack", "rotated": true})).await;
                }
                Ok(_) => send_err(tx, "TOKEN_FOREIGN", "Token gehoert fremder Session").await,
                Err(_) => send_err(tx, "TOKEN_INVALID", "Rotationstoken ungueltig").await,
            }
        }
        "ack" | "error" => {}
        other => {
            let _ = svc;
            let _ = send_err(tx, "UNKNOWN_CONTROL", other).await;
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
