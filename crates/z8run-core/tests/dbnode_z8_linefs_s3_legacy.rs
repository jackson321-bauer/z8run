//! S3b: Alt-Bestand ohne linefs_blobhash laeuft weiter; dedup greift fuer
//! neue puts, alter Bestand wird NICHT nachgeruestet (dokumentiert).

mod common;

use common::*;

#[tokio::test]
async fn altbestand_ohne_hash_index_bleibt_lesbar_und_loeschbar() {
    let base = temp_base("linefs-s3-legacy");
    let node = node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let alt = node.blob_put_bytes("d", "s", "o", "alt.bin", "application/octet-stream", b"altbestand")
        .await.unwrap();
    // Alt-Zustand simulieren: Index-Zeile existierte damals nicht.
    node.write("d", "s", "DELETE FROM linefs_blobhash WHERE sha256=?1",
        vec![alt.sha256_klartext.clone().into()]).await.unwrap();
    assert_eq!(node.blob_get_bytes("d", &alt.blob_id).await.unwrap(), b"altbestand");
    // Neuer put gleichen Inhalts: bewusst KEIN Treffer auf Altdaten.
    let neu = node.blob_put_bytes("d", "s", "o", "neu.bin", "application/octet-stream", b"altbestand")
        .await.unwrap();
    assert_ne!(alt.storage_uri, neu.storage_uri, "Altdaten werden nicht nachgeruestet");
    // Loeschen des Alt-Blobs funktioniert ohne Index-Zeile.
    node.blob_delete("d", "s", &alt.blob_id).await.unwrap();
    assert_eq!(node.blob_get_bytes("d", &neu.blob_id).await.unwrap(), b"altbestand");
}
