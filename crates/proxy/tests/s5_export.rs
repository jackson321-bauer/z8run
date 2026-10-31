//! S5: GESAMT-EXPORT — Voll-Export der Demo-Welt, Manifest-SHA je Datei,
//! PQC-Container (Passwort-Pyramide), falscher Key = Fehler, Selektion nur
//! otel, Freeze-Beweis und kein Secret im Klartext.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use proxy_kern::{DbPort, SessionState, Span, SpanStatus};
use proxy_native::export_all::{open_export, ExportRequest, World};
use proxy_native::{ProxyConfig, ProxyService, UdsDbClient};
use serde_json::{json, Value};
use tower::ServiceExt;

const SECRET: &str = "SK-EXPORT-TOPSECRET-42";
const PW: &str = "Export-Pass-2026!";

fn cluster(dir: &std::path::Path) -> Value {
    json!({
        "cluster_id": "s5",
        "local_dir": dir.join("dbnode"),
        "adapter": {"Fs": {"root": dir.join("storage")}},
    })
}

async fn write(db: &UdsDbClient, db_id: &str, sql: &str, params: Vec<Value>) {
    let _ = db.reserve(db_id, "s5").await;
    db.write(db_id, "s5", sql, params).await.unwrap();
    let _ = db.release(db_id, "s5").await;
}

fn req(worlds: Vec<World>) -> ExportRequest {
    ExportRequest {
        worlds,
        db_id: Some("demo".into()),
        sessions: Vec::new(),
        from_ms: None,
        to_ms: None,
        password: PW.into(),
        recipient_pub_b64: None,
        recipient_kem_ek_b64: None,
    }
}

#[tokio::test]
async fn gesamt_export_voll_selektiv_freeze_und_secret() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("dbnode.sock");
    let s = sock.clone();
    tokio::spawn(async move {
        let _ = z8run_core::dbnode::msg_uds::serve(s).await;
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let db = Arc::new(UdsDbClient::new(sock));
    let master = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    for id in ["demo", "otel", "meta", "meta-cluster"] {
        db.open_db(id, &master, cluster(dir.path())).await.unwrap();
    }

    // Demo-Welt: LineFS (echtes DDL), Flows, Apps.
    write(&db, "demo", z8run_core::dbnode::linefs_rows::ddl_global(), vec![]).await;
    write(
        &db,
        "demo",
        "INSERT INTO dateien (datei_id,name,art,ordner_id,status,fassung,ts,urheber) \
         VALUES (1,'notiz.txt','code',0,'text',1,'2026-10-31T10:00:00Z','tester')",
        vec![],
    )
    .await;
    write(
        &db,
        "demo",
        "INSERT INTO zeilen_epochen (datei_id,seite,schluessel,nr,seg,inhalt,ende,fassung,\
         geloescht,ts,urheber,vor_hash,hash) \
         VALUES (1,1,1,1,1,'hallo welt',1,1,0,'2026-10-31T10:00:00Z','tester','','h1')",
        vec![],
    )
    .await;
    write(&db, "demo", "CREATE TABLE flows (id TEXT, name TEXT, session TEXT, ts_ms INTEGER)", vec![]).await;
    write(
        &db,
        "demo",
        "INSERT INTO flows VALUES ('f1','Demo','sess-a',1700000000000)",
        vec![],
    )
    .await;
    write(&db, "demo", "CREATE TABLE apps (id TEXT, name TEXT, session TEXT, ts_ms INTEGER)", vec![]).await;
    write(
        &db,
        "demo",
        "INSERT INTO apps VALUES ('a1','Voice','sess-a',1700000000000)",
        vec![],
    )
    .await;

    // Blob-Session (Aufnahme) ueber die echte Engine (mit Reservierung).
    db.reserve("demo", "sess-a").await.unwrap();
    let m = db
        .blob_session_begin("demo", "sess-a", "owner-1", "video")
        .await
        .unwrap();
    let sid = m["session_id"].as_str().unwrap().to_string();
    db.blob_session_append("demo", "sess-a", &sid, b"blob-inhalt-123", 0)
        .await
        .unwrap();
    db.blob_session_finish("demo", "sess-a", &sid).await.unwrap();
    db.release("demo", "sess-a").await.unwrap();

    // OTel + Meta ueber den Dienst (Logging ist Abonnent der Naht).
    let cfg = ProxyConfig {
        otel_db: "otel".into(),
        meta_db: "meta".into(),
        cluster_meta_db: "meta-cluster".into(),
        ..ProxyConfig::default()
    };
    let db_arc: Arc<dyn DbPort> = db.clone();
    let svc = ProxyService::new(cfg).with_db(db_arc);
    svc.secrets.insert("ncp", "api_key", SECRET);
    let svc = Arc::new(svc);
    svc.write_span(Span {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: "00f067aa0ba902b7".into(),
        parent_span_id: None,
        name: "export.demo".into(),
        attrs: json!({"session": "sess-a"}),
        start_ms: 1_700_000_000_000,
        end_ms: 1_700_000_000_010,
        status: SpanStatus::Ok,
        engine_id: "proxy".into(),
        direction: None,
    })
    .await;
    svc.record_meta(
        "app",
        proxy_kern::meta::EventKind::AppCall,
        "demo",
        "",
        "sess-a",
        "ok",
        "export_test",
    )
    .await;
    for _ in 0..50 {
        let spans = svc.otel.as_ref().unwrap().all().await.unwrap();
        let meta = svc
            .meta
            .as_ref()
            .unwrap()
            .query(None, None, 100)
            .await
            .unwrap();
        if !spans.is_empty() && !meta.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // F1: Overflow-Meta ueber den ECHTEN Service-Sink (Hub -> MetaStore).
    let _ovf = svc.streams.subscribe("demo/ovf", 999).unwrap();
    for i in 0..400u32 {
        svc.streams
            .publish("demo/ovf", proxy_native::frame::TYP_MEDIA, i.to_le_bytes().to_vec())
            .unwrap();
    }
    for _ in 0..50 {
        let metas = svc.meta.as_ref().unwrap().query(None, None, 1000).await.unwrap();
        if metas.iter().any(|m| m.action == "stream_overflow") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let metas = svc.meta.as_ref().unwrap().query(None, None, 1000).await.unwrap();
    assert!(
        metas.iter().any(|m| m.action == "stream_overflow"),
        "stream_overflow nicht als Meta persistiert"
    );
    println!("OVERFLOW_META echt=ja");

    // VOLL-EXPORT
    let out = svc.export_all(&req(vec![])).await.unwrap();
    let manifest = out["manifest"].clone();
    assert!(manifest["hash_chain"].as_str().unwrap().len() == 64);
    let b64 = out["container_b64"].as_str().unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();

    // Secrets nie im Klartext (Container + Manifest).
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    assert!(!manifest.to_string().contains(SECRET));
    let sec = manifest["secrets"].as_array().unwrap();
    assert!(sec.iter().any(|s| s["name"] == "ncp/api_key"));
    assert!(sec.iter().all(|s| s.get("box").is_some()), "keine versiegelte Huelle");
    assert!(manifest.get("secret_values").is_none(), "Klartext-Huelle im Manifest");

    // Oeffnen mit Empfaenger-Passwort; jeder Datei-SHA wird geprueft.
    let (m2, files) = open_export(&bytes, PW).unwrap();
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    for want in ["spans.jsonl", "meta.jsonl", "linefs.jsonl", "flows.jsonl", "apps.jsonl", "blobs.jsonl"] {
        assert!(names.contains(&want), "Welt fehlt: {want} — {names:?}");
    }
    assert!(names.contains(&format!("blobs/{sid}.bin").as_str()));
    let blob = &files.iter().find(|(n, _)| n.ends_with(".bin")).unwrap().1;
    assert_eq!(blob, b"blob-inhalt-123");
    let linefs = String::from_utf8_lossy(&files.iter().find(|(n, _)| n == "linefs.jsonl").unwrap().1);
    assert!(linefs.contains("hallo welt"));
    assert_eq!(m2["files"].as_array().unwrap().len(), files.len());
    println!("EXPORT_VOLL files={} chain={}", files.len(), m2["hash_chain"]);

    // Falscher Key/Passwort = Fehler.
    assert!(open_export(&bytes, "falsches-Passwort-2026!").is_err());
    println!("EXPORT_KEY falsch=fehler");

    // ECHTER FREEZE: waehrend der Reservierung blockiert der Export selbst
    // (er versucht zu reservieren) UND jeder Schreiber.
    db.reserve("demo", "freeze-hold").await.unwrap();
    assert!(
        svc.export_all(&req(vec![World::Flows])).await.is_err(),
        "Export ohne Freeze-Reservierung"
    );
    assert!(
        db.write("demo", "sess-a", "INSERT INTO flows VALUES ('f2','X','sess-a',0)", vec![])
            .await
            .is_err(),
        "Schreiber trotz Freeze-Reservierung"
    );
    db.release("demo", "freeze-hold").await.unwrap();
    println!("EXPORT_FREEZE reservierung blockiert export+schreiben");

    // SELEKTION + Session-Filter + Zeitraum-Filter.
    let mut sel = req(vec![World::Flows]);
    sel.sessions = vec!["sess-a".into()];
    let m = svc.export_all(&sel).await.unwrap();
    assert_eq!(m["manifest"]["counts"]["flows"], 1);
    let mut none = req(vec![World::Flows]);
    none.sessions = vec!["niemand".into()];
    let m = svc.export_all(&none).await.unwrap();
    assert_eq!(m["manifest"]["counts"]["flows"], 0);
    let mut future = req(vec![World::Linefs]);
    future.from_ms = Some(1_900_000_000_000);
    let m = svc.export_all(&future).await.unwrap();
    assert_eq!(m["manifest"]["counts"]["linefs"], 0, "LineFS-Zeitfilter (ts)");
    let mut hit = req(vec![World::Linefs]);
    hit.from_ms = Some(1_700_000_000_000);
    hit.to_ms = Some(1_900_000_000_000);
    let m = svc.export_all(&hit).await.unwrap();
    assert_eq!(m["manifest"]["counts"]["linefs"], 2, "LineFS-Zeitfilter positiv (datei+zeile)");
    println!("EXPORT_FILTER session/zeitraum=ok");

    // Hash-Kette ist beim Oeffnen NICHT manipulierbar.
    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["manifest"]["hash_chain"] = Value::from("0".repeat(64));
    let bad = serde_json::to_vec(&tampered).unwrap();
    assert!(open_export(&bad, PW).is_err(), "manipulierte Hash-Kette akzeptiert");
    println!("EXPORT_CHAIN manipulation=fehler");

    // SELEKTION: nur otel.
    let only = svc.export_all(&req(vec![World::Otel])).await.unwrap();
    let (_, ofiles) = open_export(
        &base64::engine::general_purpose::STANDARD
            .decode(only["container_b64"].as_str().unwrap())
            .unwrap(),
        PW,
    )
    .unwrap();
    assert_eq!(ofiles.len(), 1);
    assert_eq!(ofiles[0].0, "spans.jsonl");
    assert!(!ofiles.iter().any(|(n, _)| n == "meta.jsonl"));
    println!("EXPORT_SELEKTION nur_otel=spans.jsonl");

    // FREEZE: Aktion NACH dem ersten Export ist nicht drin, im naechsten schon.
    svc.record_meta(
        "app",
        proxy_kern::meta::EventKind::AppCall,
        "demo",
        "",
        "sess-a",
        "ok",
        "nach_freeze",
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let after = svc.export_all(&req(vec![World::Meta])).await.unwrap();
    let (_, afiles) = open_export(
        &base64::engine::general_purpose::STANDARD
            .decode(after["container_b64"].as_str().unwrap())
            .unwrap(),
        PW,
    )
    .unwrap();
    let before_meta = String::from_utf8_lossy(
        &files.iter().find(|(n, _)| n == "meta.jsonl").unwrap().1,
    )
    .to_string();
    assert!(!before_meta.contains("nach_freeze"), "Freeze verletzt");
    let after_meta = String::from_utf8_lossy(&afiles[0].1).to_string();
    assert!(after_meta.contains("nach_freeze"), "neuer Export fehlt Aktion");
    println!("EXPORT_FREEZE alt_ohne=ok neu_mit=ok");

    // EINE API positiver HTTP-E2E: Token + POST /v1/export/all und /v1/stream/ctl.
    let tok = svc
        .open_session(SessionState::new(
            "s5-http".into(),
            "space".into(),
            "user".into(),
            "ws/".into(),
            json!([]),
            vec!["demo".into()],
            b"master".to_vec(),
            1,
        ))
        .token;
    let app = proxy_native::http::router(svc.clone());
    let (st, v) = post_json(
        app.clone(),
        "/v1/export/all",
        &tok,
        json!({"worlds":["meta"], "password": PW}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "HTTP-Export: {v}");
    assert_eq!(v["manifest"]["hash_chain"].as_str().unwrap().len(), 64);
    assert!(!v["container_b64"].as_str().unwrap().is_empty());
    let (st, _) = post_json(
        app.clone(),
        "/v1/stream/ctl",
        &tok,
        json!({"action":"open","channel":"api/pos"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = post_json(
        app.clone(),
        "/v1/stream/ctl",
        &tok,
        json!({"action":"claim","channel":"api/pos"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = post_json(
        app,
        "/v1/stream/ctl",
        &tok,
        json!({"action":"push","channel":"api/pos","payload_b64":"aGFsbG8="}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "ctl push: {v}");
    println!("API_HTTP export_all+stream_ctl=200");
}

async fn post_json(
    app: axum::Router,
    uri: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
        .await
        .unwrap_or_default();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}
