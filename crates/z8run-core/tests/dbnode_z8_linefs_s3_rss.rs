//! S3 (f): streamende Hash-Berechnung vor dem Dedup-Check (RSS flach).

mod common;

use common::*;
use z8run_core::dbnode::DbNode;

#[tokio::test]
async fn f_dedup_hash_streamend_rss_flach() {
    let base = std::path::PathBuf::from(format!("/data/z8run-test/tmp/linefs-s3-f-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let quelle = base.join("quelle.bin");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&quelle).unwrap();
        let block = vec![0x5Au8; 1024 * 1024];
        for _ in 0..40 {
            f.write_all(&block).unwrap();
        }
        f.flush().unwrap();
    }
    let node: DbNode = common::node();
    node.open_db("d", &master(), cluster("c", &base)).await.unwrap();
    node.reserve("d", "s").unwrap();
    let rss0 = rss_kb();
    let sampler = RssSampler::start();
    let m = node.blob_put_file("d", "s", "o", "gross.bin", "application/octet-stream", &quelle).await.unwrap();
    let peak = sampler.stop();
    let anstieg = peak.saturating_sub(rss0);
    assert!(anstieg < 10 * 1024, "Hash/Upload-RSS-Anstieg {anstieg} KiB >= 10 MB");
    println!("DEDUP_HASH_RSS_KIB={anstieg} sha={}", m.sha256_klartext);
    let _ = std::fs::remove_dir_all(&base);
}
