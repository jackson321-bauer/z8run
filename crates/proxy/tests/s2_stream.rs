//! S2: /v1/stream — Auth, Token-Rotation, duplex-Roundtrip und Live-API-
//! Relay (100 JSON + 100 Binaer gemischt, Bytes identisch, Reihenfolge).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use proxy_kern::SessionState;
use proxy_native::frame::{Frame, TYP_MEDIA};
use proxy_native::{http, ProxyConfig, ProxyService};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

fn service() -> (Arc<ProxyService>, String) {
    let svc = Arc::new(ProxyService::new(ProxyConfig::default()));
    let state = SessionState::new(
        "s2-stream".into(),
        "space".into(),
        "user".into(),
        "ws/".into(),
        json!([]),
        vec!["demo".into()],
        b"master".to_vec(),
        1,
    );
    let token = svc.open_session(state).token;
    (svc, token)
}

async fn server(svc: Arc<ProxyService>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, http::router(svc)).await.unwrap();
    });
    format!("ws://{addr}/v1/stream")
}

async fn connect(
    url: &str,
    token: Option<&str>,
    typ: &str,
    channel: &str,
    peer: Option<&str>,
    identity: &str,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, String> {
    let mut req = url.into_client_request().map_err(|e| e.to_string())?;
    if let Some(t) = token {
        req.headers_mut()
            .insert("authorization", HeaderValue::from_str(&format!("Bearer {t}")).unwrap());
    }
    req.headers_mut()
        .insert("x-z8-stream-type", HeaderValue::from_str(typ).unwrap());
    req.headers_mut()
        .insert("x-z8-channel", HeaderValue::from_str(channel).unwrap());
    req.headers_mut()
        .insert("x-z8-identity", HeaderValue::from_str(identity).unwrap());
    if let Some(p) = peer {
        req.headers_mut()
            .insert("x-z8-peer-channel", HeaderValue::from_str(p).unwrap());
    }
    tokio_tungstenite::connect_async(req)
        .await
        .map(|(ws, _)| ws)
        .map_err(|e| e.to_string())
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn send_bin(ws: &mut Ws, bytes: &[u8]) {
    let framed = Frame::with_flags(TYP_MEDIA, 0, 1, 0, bytes.to_vec())
        .unwrap()
        .encode()
        .unwrap();
    ws.send(Message::Binary(framed.into())).await.unwrap();
}

async fn recv_bin(ws: &mut Ws) -> Vec<u8> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("Timeout beim Empfang")
            .expect("Socket zu")
            .expect("WS-Fehler");
        match msg {
            Message::Binary(b) => return b.to_vec(),
            Message::Text(_) | Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("Unerwartet: {other:?}"),
        }
    }
}

async fn recv_text(ws: &mut Ws) -> Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("Timeout")
            .expect("Socket zu")
            .expect("WS-Fehler");
        if let Message::Text(t) = msg {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v["type"] != "heartbeat" {
                    return v;
                }
            }
        }
    }
}

#[tokio::test]
async fn upgrade_ohne_token_abgewiesen() {
    let (svc, _tok) = service();
    let url = server(svc).await;
    let err = connect(&url, None, "live", "app/x", None, "u").await;
    assert!(err.is_err(), "Upgrade ohne Token wurde akzeptiert");
    println!("WS_AUTH ohne_token=abgewiesen");
}

#[tokio::test]
async fn token_rotation_im_socket_und_live_roundtrip() {
    let (svc, token) = service();
    let url = server(svc.clone()).await;
    let mut ws = connect(&url, Some(&token), "live", "app/live", None, "engine-1").await.unwrap();
    send_bin(&mut ws, b"vor-rotation").await;
    let ack = recv_text(&mut ws).await;
    assert_eq!(ack["type"], "ack");
    assert_eq!(ack["seq"], 0);
    // G2: Binaerrahmen OHNE 16-B-Header wird abgewiesen (kein Raten).
    ws.send(Message::Binary(vec![0u8; 32].into())).await.unwrap();
    let badframe = recv_text(&mut ws).await;
    assert_eq!(badframe["code"], "BAD_FRAME");

    // Rotation IN der Socket (Control-Frame): Verbindung lebt weiter.
    let grant = svc.rotate(&token).unwrap();
    assert_ne!(grant.token, token);
    ws.send(Message::Text(
        json!({"type": "token", "token": grant.token}).to_string().into(),
    ))
    .await
    .unwrap();
    let rot = recv_text(&mut ws).await;
    assert_eq!(rot["type"], "ack");
    assert_eq!(rot["rotated"], true);
    // Ungueltiges Rotationstoken wird abgewiesen, Socket bleibt.
    ws.send(Message::Text(
        json!({"type": "token", "token": "kaputt"}).to_string().into(),
    ))
    .await
    .unwrap();
    let bad = recv_text(&mut ws).await;
    assert_eq!(bad["code"], "TOKEN_INVALID");
    send_bin(&mut ws, b"nach-rotation").await;
    let ack2 = recv_text(&mut ws).await;
    assert_eq!(ack2["seq"], 1);

    // Subscriber sieht beide Frames unveraendert, in Reihenfolge.
    let mut sub = connect(&url, Some(&grant.token), "subscribe", "app/live", None, "app-1")
        .await
        .unwrap();
    send_bin(&mut ws, b"nach-subscribe").await;
    let f = recv_bin(&mut sub).await;
    assert_eq!(f.len(), 16 + "nach-subscribe".len());
    assert_eq!(&f[16..], b"nach-subscribe");
    println!("WS_ROTATION socket_lebt=ja neuer_token=ja seq=2");
}

#[tokio::test]
async fn duplex_roundtrip_zwei_kanaele() {
    let (svc, token) = service();
    let url = server(svc).await;
    let mut a = connect(&url, Some(&token), "duplex", "call/a", Some("call/b"), "alice")
        .await
        .unwrap();
    let mut b = connect(&url, Some(&token), "duplex", "call/b", Some("call/a"), "bob")
        .await
        .unwrap();

    send_bin(&mut a, b"a-nach-b").await;
    let got_b = recv_bin(&mut b).await;
    assert_eq!(&got_b[16..], b"a-nach-b");

    send_bin(&mut b, b"b-nach-a").await;
    let got_a = recv_bin(&mut a).await;
    assert_eq!(&got_a[16..], b"b-nach-a");
    println!("DUPLEX a->b=ok b->a=ok");
}

#[tokio::test]
async fn live_api_relay_200_frames_gemischt_bytes_identisch() {
    let (svc, token) = service();
    let url = server(svc).await;
    let mut producer = connect(&url, Some(&token), "relay", "rt/a", Some("rt/b"), "app").await.unwrap();
    let mut consumer = connect(&url, Some(&token), "relay", "rt/b", Some("rt/a"), "app2").await.unwrap();

    let mut expected: Vec<Vec<u8>> = Vec::new();
    for i in 0..100u32 {
        let json_event = json!({"type": "response.audio.delta", "seq": i, "text": format!("ereignis-{i}")});
        let bytes = serde_json::to_vec(&json_event).unwrap();
        expected.push(bytes.clone());
        send_bin(&mut producer, &bytes).await;
        assert_eq!(recv_bin(&mut consumer).await[16..], bytes[..]);

        let mut audio = vec![0u8; 320];
        audio[0] = i as u8;
        audio[319] = 0xFF;
        expected.push(audio.clone());
        send_bin(&mut producer, &audio).await;
        assert_eq!(recv_bin(&mut consumer).await[16..], audio[..]);
    }
    assert_eq!(expected.len(), 200);
    println!("RELAY frames=200 json=100 binaer=100 bytes=identisch reihenfolge=ok");
}

#[tokio::test]
async fn fremde_identitaet_claim_abgewiesen() {
    let (svc, token) = service();
    // ZWEITE Session = zweite Identitaet (Identitaet ist die Session).
    let state2 = SessionState::new(
        "s2-stream-2".into(),
        "space".into(),
        "user".into(),
        "ws/".into(),
        json!([]),
        vec!["demo".into()],
        b"master".to_vec(),
        1,
    );
    let token2 = svc.open_session(state2).token;
    let url = server(svc).await;
    let _a = connect(&url, Some(&token), "live", "app/claim", None, "alice").await.unwrap();
    let mut b = connect(&url, Some(&token2), "live", "app/claim", None, "alice").await.unwrap();
    let err = recv_text(&mut b).await;
    assert_eq!(err["type"], "err");
    assert_eq!(err["code"], "CLAIM_DENIED");
    println!("WS_CLAIM fremde_identitaet=abgewiesen");
}
