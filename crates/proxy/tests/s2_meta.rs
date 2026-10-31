//! S2: Meta-Welt — 12 Ereignis-Arten, Inhalts-Negativtest, WORM, global.

use std::sync::Arc;

use base64::Engine as _;
use proxy_kern::{EventKind, MetaEvent};
use proxy_kern::DbPort;
use proxy_native::{MetaStore, UdsDbClient};
use serde_json::json;

fn cluster(dir: &std::path::Path) -> serde_json::Value {
    json!({
        "cluster_id": "cluster-meta",
        "local_dir": dir.join("dbnode"),
        "adapter": {"Fs": {"root": dir.join("storage")}},
    })
}

#[tokio::test]
async fn meta_decke_negativ_worm_und_global() {
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
    let db = UdsDbClient::new(sock);
    let master = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    for db_id in ["meta", "meta-cluster"] {
        db.open_db(db_id, &master, cluster(dir.path())).await.unwrap();
    }
    let db_arc: Arc<dyn proxy_kern::DbPort> = Arc::new(db);
    let store = MetaStore::new(db_arc, vec!["meta".into(), "meta-cluster".into()]);

    // Die 12 Ereignis-Arten, je ein Beispiel.
    for (i, kind) in EventKind::all().iter().enumerate() {
        let e = MetaEvent::new(
            "system",
            *kind,
            &format!("obj-{i}"),
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "sess-1",
            "ok",
            kind.as_str(),
            i as u64,
        )
        .unwrap();
        store.record(&e).await.unwrap();
        println!("META art={} actor={} status={}", e.action, e.actor, e.status);
    }
    let all = store.query(None, None, 100).await.unwrap();
    assert_eq!(all.len(), 12, "Ereignis-Decke unvollstaendig: {all:?}");
    let mut actions: Vec<String> = all.iter().map(|e| e.action.clone()).collect();
    actions.sort();
    actions.dedup();
    assert_eq!(actions.len(), 12, "nicht alle 12 Arten geschrieben");

    // Cluster-Ereignis ist in der User-Meta-Welt (global) sichtbar.
    let by_trace = store
        .query(Some("4bf92f3577b34da6a3ce929d0e0e4736"), None, 100)
        .await
        .unwrap();
    assert_eq!(by_trace.len(), 12);
    let login_only = store.query(None, Some("login"), 100).await.unwrap();
    assert_eq!(login_only.len(), 1);

    // Negativtest: Inhaltsdaten im detail-Feld werden abgelehnt.
    let bad = MetaEvent::new(
        "app",
        EventKind::AppCall,
        "echo",
        "0af7651916cd43dd8448eb211c80319c",
        "sess-1",
        "ok",
        "echo streng-geheim",
        1,
    )
    .unwrap();
    let err = store.record_guarded(&bad, "streng-geheim").await;
    assert!(err.is_err(), "Inhalt im Meta wurde nicht abgelehnt");

    // WORM: DELETE auf der Meta-Tabelle wird von der DB (Trigger) abgelehnt.
    let del = store.delete_all_raw().await;
    assert!(del.is_err(), "WORM verletzt: DELETE ging durch");
    let after = store.query(None, None, 100).await.unwrap();
    assert_eq!(after.len(), 12, "Meta-Zeilen nach Loeschversuch veraendert");
    println!("META_WORM ok delete_err={:?} rows={}", del.err().map(|e| e.code()), after.len());
}
