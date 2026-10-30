//! S1 (e): 100-MB-Blob-Upload/Download ohne RSS-Anstieg > 10 MB über Grundlast.

mod common;

use common::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

fn file_sha(path: &std::path::Path) -> String {
    let mut f = std::fs::File::open(path).unwrap();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut h = Sha256::new();
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    hex::encode(h.finalize())
}

#[tokio::test]
async fn e_100mb_upload_download_rss_flach() {
    let base = std::path::PathBuf::from(format!(
        "/data/z8run-test/tmp/blob-e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let quelle = base.join("quelle.bin");
    let mut f = std::fs::File::create(&quelle).unwrap();
    let block = vec![0x42u8; 1024 * 1024];
    for i in 0..100usize {
        let mut b = block.clone();
        b[0] = i as u8;
        f.write_all(&b).unwrap();
    }
    f.flush().unwrap();
    drop(f);
    assert_eq!(std::fs::metadata(&quelle).unwrap().len(), 100 * 1024 * 1024);

    let node = node();
    node.open_db("db-e", &master(), cluster("c1", &base)).await.unwrap();
    node.reserve("db-e", "s").unwrap();

    let rss0 = rss_kb();
    let sampler = RssSampler::start();
    let m = node
        .blob_put_file("db-e", "s", "o", "gross.bin", "application/octet-stream", &quelle)
        .await
        .unwrap();
    let peak_up = sampler.stop();
    let up = peak_up.saturating_sub(rss0);
    assert!(up < 10 * 1024, "Upload-RSS-Anstieg {up} KiB >= 10 MB");

    let ziel = base.join("ziel.bin");
    let rss1 = rss_kb();
    let sampler = RssSampler::start();
    node.blob_get_to_file("db-e", &m.blob_id, &ziel).await.unwrap();
    let peak_down = sampler.stop();
    let down = peak_down.saturating_sub(rss1);
    assert!(down < 10 * 1024, "Download-RSS-Anstieg {down} KiB >= 10 MB");

    assert_eq!(file_sha(&quelle), file_sha(&ziel), "100MB-SHA256");
    println!("RSS_UP_KIB={up} RSS_DOWN_KIB={down} RSS0={rss0}");

    let _ = std::fs::remove_dir_all(&base);
}
