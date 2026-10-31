//! Socket-Schleife des Stream-Endpoints. Medienpfad = Binaer; nur Control-
//! Frames (Text) werden als JSON gelesen. Kein JSON-Parse auf Binaerdaten.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use crate::channel::ChannelRegistry;
use crate::frame::{Frame, FRAME_MAGIC, HEADER_LEN, TYP_MEDIA};
use crate::service::ProxyService;
use crate::stream::Setup;
use proxy_kern::meta::MetaEvent;

fn next_socket_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

async fn send_json(tx: &mpsc::Sender<Message>, v: Value) -> bool {
    tx.send(Message::Text(v.to_string().into())).await.is_ok()
}

async fn send_err(tx: &mpsc::Sender<Message>, code: &str, message: &str) {
    let _ = send_json(tx, json!({"type": "err", "code": code, "error": message})).await;
}

fn unwrap_media(data: &Bytes) -> (u8, Vec<u8>) {
    if data.len() >= HEADER_LEN && u16::from_be_bytes([data[0], data[1]]) == FRAME_MAGIC {
        if let Ok(f) = Frame::decode(data) {
            return (f.typ, f.payload);
        }
    }
    (TYP_MEDIA, data.to_vec())
}

async fn record_overflow(svc: &ProxyService, channel: &str, session: &str, dropped: u64) {
    let event = MetaEvent {
        actor: "system".into(),
        action: "stream_overflow".into(),
        object_ref: channel.to_string(),
        trace_id: String::new(),
        session: session.to_string(),
        status: "ok".into(),
        detail: format!("stream_overflow dropped={dropped}"),
        ts_ms: svc.now_ms(),
    };
    if event.validate().is_err() {
        return;
    }
    let payload = json!({"meta": serde_json::to_value(&event).unwrap_or(Value::Null)});
    svc.hub
        .publish(&svc.cfg.cluster_id, "proxy", "meta:stream_overflow", "", payload)
        .await;
}

async fn spawn_forward(
    reg: Arc<ChannelRegistry>,
    sub: Arc<crate::subscriber::Subscriber>,
    tx: mpsc::Sender<Message>,
) {
    while let Some(raw) = reg.recv(&sub).await {
        if tx.send(Message::Binary(raw.to_vec().into())).await.is_err() {
            break;
        }
    }
}

pub async fn handle(mut socket: WebSocket, svc: Arc<ProxyService>, setup: Setup) {
    let sid = next_socket_id();
    let reg = svc.streams.clone();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let mut writable = std::collections::HashSet::new();
    let mut joined: Vec<String> = Vec::new();

    if let Some(own) = &setup.own {
        match reg.claim(own, &setup.identity, sid) {
            Ok(grant) => {
                writable.insert(own.clone());
                joined.push(own.clone());
                svc.record_meta(
                    "app",
                    proxy_kern::meta::EventKind::AppCall,
                    own,
                    "",
                    &setup.session_id,
                    "ok",
                    &format!("stream_claim sid={}", grant.stream_id),
                )
                .await;
            }
            Err(_) => {
                let _ = send_err(&out_tx, "CLAIM_DENIED", "Claim gehoert fremder Identitaet").await;
                let _ = socket.send(out_rx.recv().await.unwrap_or(Message::Close(None))).await;
                return;
            }
        }
    }
    for ch in &setup.subscribe {
        match reg.subscribe(ch, sid) {
            Ok(sub) => {
                joined.push(ch.clone());
                tokio::spawn(spawn_forward(reg.clone(), sub, out_tx.clone()));
            }
            Err(_) => {
                let _ = send_err(&out_tx, "SUBSCRIBE_FAILED", ch).await;
            }
        }
    }
    if !joined.is_empty() {
        svc.record_meta(
            "app",
            proxy_kern::meta::EventKind::AppCall,
            joined.first().map(String::as_str).unwrap_or("stream"),
            "",
            &setup.session_id,
            "ok",
            &format!("stream_open type={:?} channels={}", setup.kind, joined.len()),
        )
        .await;
    }

    let (mut sink, mut stream) = socket.split();
    let writer_stop = stop_tx.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let hb = json!({"type": "heartbeat", "ts_ms": now_ms()}).to_string();
                    if sink.send(Message::Text(hb.into())).await.is_err() { break; }
                }
                msg = out_rx.recv() => match msg {
                    Some(m) => { if sink.send(m).await.is_err() { break; } }
                    None => break,
                }
            }
        }
        let _ = writer_stop.send(true);
    });

    loop {
        tokio::select! {
            _ = stop_rx.changed() => break,
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    let Some(ch) = first_writable(&writable) else {
                        let _ = send_err(&out_tx, "NOT_CLAIMED", "Socket haelt keinen Claim").await;
                        continue;
                    };
                    let (typ, payload) = unwrap_media(&data);
                    match reg.publish(ch, typ, payload) {
                        Ok(out) => {
                            let _ = send_json(&out_tx, json!({"type": "ack", "seq": out.seq})).await;
                            if out.overflowed > 0 {
                                let svc = svc.clone();
                                let ch = ch.to_string();
                                let session = setup.session_id.clone();
                                tokio::spawn(async move {
                                    record_overflow(&svc, &ch, &session, out.overflowed).await;
                                });
                            }
                        }
                        Err(e) => send_err(&out_tx, e.code(), &e.to_string()).await,
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        handle_control(&svc, &reg, &mut writable, &mut joined, &out_tx, &setup, sid, &v).await;
                    } else {
                        let _ = send_err(&out_tx, "BAD_CONTROL", "Control-Frame kein JSON").await;
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = out_tx.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            }
        }
    }

    for ch in &joined {
        if writable.contains(ch) {
            reg.disconnect(ch, sid);
        } else {
            reg.unsubscribe(ch, sid);
        }
    }
    let _ = stop_tx.send(true);
    drop(out_tx);
}

fn first_writable(set: &std::collections::HashSet<String>) -> Option<&str> {
    set.iter().next().map(String::as_str)
}

#[allow(clippy::too_many_arguments)]
async fn handle_control(
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
            let identity = v.get("identity").and_then(Value::as_str).unwrap_or(&setup.identity);
            match reg.claim(ch, identity, sid) {
                Ok(g) => {
                    writable.insert(ch.to_string());
                    if !joined.contains(&ch.to_string()) {
                        joined.push(ch.to_string());
                    }
                    let _ = send_json(tx, json!({"type": "ack", "claimed": ch, "stream_id": g.stream_id})).await;
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
        "ack" => {}
        "error" => {}
        other => {
            let _ = svc;
            let _ = send_err(tx, "UNKNOWN_CONTROL", other).await;
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

