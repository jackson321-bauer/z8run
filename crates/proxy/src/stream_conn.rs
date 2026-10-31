//! Socket-Schleife des Stream-Endpoints. Medienpfad = Binaer; nur Control-
//! Frames (Text) werden als JSON gelesen. Kein JSON-Parse auf Binaerdaten.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use crate::channel::ChannelRegistry;
use crate::frame::Frame;
use crate::service::ProxyService;
use crate::stream::Setup;
use crate::stream_control::handle_control;

fn next_socket_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub(crate) async fn send_json(tx: &mpsc::Sender<Message>, v: Value) -> bool {
    tx.send(Message::Text(v.to_string().into())).await.is_ok()
}

pub(crate) async fn send_err(tx: &mpsc::Sender<Message>, code: &str, message: &str) {
    let _ = send_json(tx, json!({"type": "err", "code": code, "error": message})).await;
}

pub(crate) async fn spawn_forward(
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
                let msg = out_rx.recv().await.unwrap_or(Message::Close(None));
                let _ = socket.send(msg).await;
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
                    let hb = json!({"type": "heartbeat", "ts_ms": crate::stream_control::now_ms()})
                        .to_string();
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
                    let Some(ch) = writable.iter().next().cloned() else {
                        let _ = send_err(&out_tx, "NOT_CLAIMED", "Socket haelt keinen Claim").await;
                        continue;
                    };
                    // G2: Medien-Frames sind Binaer MIT 16-B-Header. Es wird
                    // NICHT geraten — ein Rahmen ohne gueltigen Header wird
                    // abgewiesen (kein versehentliches Abschneiden von Inhalt).
                    match Frame::decode(&data) {
                        Ok(f) => match reg.publish_with_flags(&ch, f.typ, f.flags, f.payload) {
                            Ok(out) => {
                                let _ =
                                    send_json(&out_tx, json!({"type": "ack", "seq": out.seq}))
                                        .await;
                            }
                            Err(e) => send_err(&out_tx, e.code(), &e.to_string()).await,
                        },
                        Err(e) => send_err(&out_tx, "BAD_FRAME", &e.to_string()).await,
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        handle_control(
                            &svc, &reg, &mut writable, &mut joined, &out_tx, &setup, sid, &v,
                        )
                        .await;
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
