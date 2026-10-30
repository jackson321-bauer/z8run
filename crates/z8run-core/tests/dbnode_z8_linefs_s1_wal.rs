//! S1 (f)-(h): WAL art:linefs mit lueckenloser prev_hash-Kette,
//! SQL+Zeilen-Interleaving, render_fuer_prozess RAII.

mod common;

use base64::Engine;
use common::*;
use serde_json::{json, Value};
use std::path::Path;
use z8run_core::dbnode::crypto::KeyEnvelope;
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::wal::{WalInner, WalObject};
use z8run_core::dbnode::DbNode;

async fn lf(node: &DbNode, db: &str, s: &str, aktion: LinefsAktion) -> Value {
    node.linefs(LinefsRequest { db_id: db.into(), session_id: s.into(), aktion })
        .await
        .unwrap()
}

fn wal_dateien(base: &Path, db: &str) -> Vec<(u64, WalObject)> {
    let dir = base.join("c").join(db).join("wal");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let nr: u64 = p.file_stem().unwrap().to_string_lossy().parse().unwrap();
        let obj: WalObject = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        out.push((nr, obj));
    }
    out.sort_by_key(|(n, _)| *n);
    out
}

fn kette_pruefen(base: &Path, db: &str, key: &KeyEnvelope) -> (usize, usize) {
    let mut prev = String::new();
    let mut linefs = 0usize;
    let mut sql = 0usize;
    for (erwartet, (nr, obj)) in (1u64..).zip(wal_dateien(base, db)) {
        assert_eq!(nr, erwartet, "WAL-Luecke");
        assert_eq!(obj.prev_hash, prev, "prev_hash-Kette bei {nr}");
        let sealed = base64::engine::general_purpose::STANDARD.decode(&obj.seal).unwrap();
        let plain = z8run_core::dbnode::crypto::open(key, db, nr, &obj.prev_hash, &sealed).unwrap();
        let inner: WalInner = serde_json::from_slice(&plain).unwrap();
        match inner.art.as_str() {
            "linefs" => {
                assert!(!inner.ops.is_empty());
                linefs += 1;
            }
            _ => sql += 1,
        }
        prev = obj.hash;
    }
    (linefs, sql)
}

#[tokio::test]
async fn f_wal_enthaelt_linefs_commit_mit_lueckenloser_kette() {
    let base = temp_base("linefs-f");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "w.txt".into(), art: "code".into(), text: "a\nb\nc".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsOeffnen { pfad: "w.txt".into() }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsZeileSetzen { nr: 1, inhalt: "A".into() }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsSchliessen).await;
    node.write("d", "s", "CREATE TABLE t (x INTEGER)", vec![]).await.unwrap();

    let key = KeyEnvelope::derive(&master(), "d").unwrap();
    let (linefs, sql) = kette_pruefen(&base, "d", &key);
    assert!(linefs >= 2, "Anlegen + Schliessen: {linefs}");
    assert!(sql >= 1, "SQL-Write im selben Strom: {sql}");
    let q = node.query("d", "SELECT count(*), max(nr) FROM _z8_line_epochs", &[]).unwrap();
    let count = q.rows[0][0].as_i64().unwrap();
    let max = q.rows[0][1].as_i64().unwrap();
    assert_eq!(count, max, "Zeilen-Epochen lueckenlos");
    assert_eq!(count as usize, linefs + sql);
}

#[tokio::test]
async fn g_gleichzeitige_sql_und_zeilen_writes_konsistent() {
    let base = temp_base("linefs-g");
    let node = node();
    node.open_db("g", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("g", "s").unwrap();
    node.write("g", "s", "CREATE TABLE t (x INTEGER)", vec![]).await.unwrap();
    lf(&node, "g", "s", LinefsAktion::LinefsAnlegen {
        name: "f.txt".into(), art: "code".into(), text: "a\nb".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    lf(&node, "g", "s", LinefsAktion::LinefsOeffnen { pfad: "f.txt".into() }).await;
    lf(&node, "g", "s", LinefsAktion::LinefsZeileSetzen { nr: 1, inhalt: "A".into() }).await;

    let sql = node.write("g", "s", "INSERT INTO t(x) VALUES (?1)", vec![json!(1)]);
    let lin = node.linefs(LinefsRequest {
        db_id: "g".into(), session_id: "s".into(),
        aktion: LinefsAktion::LinefsSchliessen,
    });
    let (a, b) = tokio::join!(sql, lin);
    a.unwrap();
    b.unwrap();

    let key = KeyEnvelope::derive(&master(), "g").unwrap();
    let (linefs, sql) = kette_pruefen(&base, "g", &key);
    assert!(linefs >= 2 && sql >= 2, "arts: linefs={linefs} sql={sql}");
    let q = node.query("g", "SELECT count(*), max(nr) FROM _z8_line_epochs", &[]).unwrap();
    assert_eq!(q.rows[0][0], q.rows[0][1], "WAL-Reihenfolge konsistent");
}

#[tokio::test]
async fn h_render_fuer_prozess_byte_identisch_und_weggeraeumt() {
    let base = temp_base("linefs-h");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let text = "zeile1\nzeile2\r\nende";
    lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "r.txt".into(), art: "code".into(), text: text.into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    let r = lf(&node, "d", "s", LinefsAktion::LinefsRenderFuerProzess {
        pfad: "r.txt".into(), prozess_id: "p1".into(),
    }).await;
    let p = r["pfad"].as_str().unwrap().to_string();
    assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
    assert!(Path::new(&p).exists());
    let e = lf(&node, "d", "s", LinefsAktion::LinefsProzessEnde { prozess_id: "p1".into() }).await;
    assert_eq!(e["rest"], 0);
    assert!(!Path::new(&p).exists(), "keine Leiche im Adapter-Pfad");
    assert!(!Path::new(&p).parent().unwrap().exists());
}

#[tokio::test]
async fn i_stale_render_wird_bei_reopen_und_close_entfernt() {
    let base = temp_base("linefs-i");
    let stale = base.join("c").join("tmp").join("linefs-render").join("alt");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("leiche"), b"x").unwrap();
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    assert!(!stale.parent().unwrap().exists(), "Stale-Render beim Oeffnen gefegt");
    node.reserve("d", "s").unwrap();
    lf(&node, "d", "s", LinefsAktion::LinefsAnlegen {
        name: "r.txt".into(), art: "code".into(), text: "x".into(),
        urheber: "ki".into(), ordner_id: None,
    }).await;
    lf(&node, "d", "s", LinefsAktion::LinefsRenderFuerProzess {
        pfad: "r.txt".into(), prozess_id: "p".into(),
    }).await;
    let dir = base.join("c").join("tmp").join("linefs-render");
    assert!(dir.exists());
    node.close_db("d").unwrap();
    assert!(!dir.exists(), "Close raeumt Renderkopien");
}
