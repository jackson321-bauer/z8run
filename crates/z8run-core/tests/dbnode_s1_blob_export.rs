//! S1 (j): PQC-Container — v3-Box an Empfänger, Passwort (Argon2id ∥ ML-KEM),
//! Klartext nur mit Bestätigung; falsche Keys/Passwörter = FEHLER.

mod common;

use common::*;
use z8run_core::dbnode::{BoxMode, OpenBox};
use z8run_core::nodes::setup_nodes::{setup_crypto, setup_pqc};

#[tokio::test]
async fn j_pqc_container_export_import() {
    let base = temp_base("blob-j");
    let node = node();
    node.open_db("db-j", &master(), cluster("c1", &base)).await.unwrap();
    node.reserve("db-j", "s").unwrap();
    let plain = b"PQC-CONTAINER-KLARTEXT-2026-vertraulich".to_vec();
    let m = node
        .blob_put_bytes("db-j", "s", "jason", "akte.bin", "application/octet-stream", &plain)
        .await
        .unwrap();

    // Empfänger-Identität (v3: P-256 + ML-KEM-1024).
    let ich = setup_crypto::gen_pem().unwrap();
    let kem = setup_pqc::gen_pqc().unwrap();
    let container = node
        .blob_export_container(
            "db-j",
            &m.blob_id,
            BoxMode::Pqc { pub_b64: &ich.pub_b64, kem_ek_b64: &kem.ek_b64 },
        )
        .await
        .unwrap();
    let out = z8run_core::dbnode::DbNode::blob_open_container(
        &container,
        OpenBox::Pqc { pem: &ich.pem, kem_dk: &kem.dk },
    )
    .unwrap();
    assert_eq!(out, plain, "PQC-Container Roundtrip");

    // Falscher Empfänger-Key = FEHLER.
    let fremd = setup_crypto::gen_pem().unwrap();
    let fremd_kem = setup_pqc::gen_pqc().unwrap();
    assert!(z8run_core::dbnode::DbNode::blob_open_container(
        &container,
        OpenBox::Pqc { pem: &fremd.pem, kem_dk: &fremd_kem.dk },
    )
    .is_err());

    // Passwort-Variante: öffnet nur mit Passwort.
    let stark = "Korrekt-Pferd-2026!x";
    let pw_container = node
        .blob_export_container("db-j", &m.blob_id, BoxMode::Password { passwort: stark })
        .await
        .unwrap();
    let pw_out = z8run_core::dbnode::DbNode::blob_open_container(
        &pw_container,
        OpenBox::Password { passwort: stark },
    )
    .unwrap();
    assert_eq!(pw_out, plain);
    assert!(z8run_core::dbnode::DbNode::blob_open_container(
        &pw_container,
        OpenBox::Password { passwort: "Falsch-Pferd-2026!x" },
    )
    .is_err());

    // Schwaches Passwort = Policy-Fehler.
    let schwach = node
        .blob_export_container("db-j", &m.blob_id, BoxMode::Password { passwort: "kurz" })
        .await
        .unwrap_err();
    assert_eq!(schwach.code, "WEAK_PASSWORD");

    // Klartext-Export NUR mit Bestätigung.
    let ohne = node
        .blob_export_container("db-j", &m.blob_id, BoxMode::Plaintext { bestaetigung: false })
        .await
        .unwrap_err();
    assert_eq!(ohne.code, "CONFIRM_REQUIRED");
    let klartext = node
        .blob_export_container("db-j", &m.blob_id, BoxMode::Plaintext { bestaetigung: true })
        .await
        .unwrap();
    let kt = z8run_core::dbnode::DbNode::blob_open_container(&klartext, OpenBox::Plaintext).unwrap();
    assert_eq!(kt, plain);
}
