//! Last-Workloads der Folter (G10): jeder Aufruf misst am Endpunkt.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_native::channel::{ChannelConfig, ChannelRegistry};
use proxy_native::frame::TYP_MEDIA;
use proxy_native::recording::Recording;

use super::memdb::MemDb;

pub fn registry(cfg: ChannelConfig) -> Arc<ChannelRegistry> {
    Arc::new(ChannelRegistry::new(cfg, Arc::new(proxy_native::SystemClock)))
}

pub async fn fanout(reg: Arc<ChannelRegistry>, round: u64) -> (usize, usize) {
    let ch = "folter/fanout".to_string();
    reg.open(&ch).unwrap();
    let mut tasks = Vec::new();
    for s in 0..100u64 {
        let sub = reg.subscribe(&ch, s).unwrap();
        let r = reg.clone();
        tasks.push(tokio::spawn(async move {
            let mut n = 0;
            while r.recv(&sub).await.is_some() {
                n += 1;
            }
            n
        }));
    }
    for i in 0..1000u32 {
        reg.publish(&ch, TYP_MEDIA, i.to_be_bytes().to_vec()).unwrap();
    }
    for s in 0..100u64 {
        reg.unsubscribe(&ch, s);
    }
    let mut min = usize::MAX;
    let mut total = 0;
    for t in tasks {
        let n = t.await.unwrap();
        total += n;
        min = min.min(n);
    }
    (total, min)
}

pub async fn recording(reg: Arc<ChannelRegistry>, db: Arc<MemDb>, round: u64) -> u64 {
    let mut lost = 0;
    for c in 0..20u64 {
        let ch = format!("folter/vnc-{c}");
        reg.open(&ch).unwrap();
        let rec = Recording::start(db.clone(), "mem".into(), "folter".into(), "s".into(), "video".into());
        reg.set_tap(&ch, Some(rec.clone())).unwrap();
        for i in 0..30u32 {
            let mut p = vec![0u8; 4096];
            p[..4].copy_from_slice(&i.to_le_bytes());
            reg.publish(&ch, TYP_MEDIA, p).unwrap();
        }
        rec.finish();
        let m = rec.wait_finished().await.unwrap();
        let got = m["chunk_ids"].as_array().map(|a| a.len()).unwrap_or(0);
        lost += 30usize.saturating_sub(got) as u64;
        reg.set_tap(&ch, None).unwrap();
    }
    lost
}

pub async fn phone(reg: Arc<ChannelRegistry>, round: u64) -> u64 {
    // 40 Gespraeche, BIDIREKTIONAL: je 2 Kanaele (A->B, B->A), 50 Frames
    // im 20-ms-Takt (native Telefonie-Frames, kein Rebundling).
    let counter = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for c in 0..40u64 {
        for dir in 0..2u64 {
            let reg = reg.clone();
            let counter = counter.clone();
            tasks.push(tokio::spawn(async move {
                let ch = format!("folter/phone-{c}-{dir}");
                reg.open(&ch).unwrap();
                for i in 0..50u32 {
                    let mut p = vec![0u8; 160];
                    p[..4].copy_from_slice(&i.to_le_bytes());
                    reg.publish(&ch, TYP_MEDIA, p).unwrap();
                    counter.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }));
        }
    }
    for t in tasks {
        let _ = t.await;
    }
    counter.load(Ordering::Relaxed)
}

pub async fn small_events(reg: Arc<ChannelRegistry>, round: u64, count: u64) -> u64 {
    let ch = "folter/events".to_string();
    reg.open(&ch).unwrap();
    let sub = reg.subscribe(&ch, 999).unwrap();
    let r = reg.clone();
    let reader = tokio::spawn(async move {
        let mut n = 0u64;
        while r.recv(&sub).await.is_some() {
            n += 1;
        }
        n
    });
    for i in 0..count {
        let line = format!("{{\"seq\":{i},\"text\":\"klein\"}}");
        reg.publish(&ch, TYP_MEDIA, line.into_bytes()).unwrap();
        if i % 1000 == 0 {
            tokio::task::yield_now().await;
        }
    }
    reg.unsubscribe(&ch, 999);
    let seen = reader.await.unwrap();
    count.saturating_sub(seen)
}

/// Relay-Latenz p99 in Mikrosekunden (publish -> Abonnent).
pub async fn relay_p99(reg: Arc<ChannelRegistry>, round: u64, frames: u64) -> u64 {
    let ch = "folter/relay".to_string();
    reg.open(&ch).unwrap();
    let sub = reg.subscribe(&ch, 1).unwrap();
    let r = reg.clone();
    let base = Instant::now();
    let reader_base = base;
    let reader = tokio::spawn(async move {
        let mut lat = Vec::new();
        while let Some(raw) = r.recv(&sub).await {
            let f = proxy_native::Frame::decode(&raw).unwrap();
            if f.payload.len() < 8 {
                continue;
            }
            let sent_ns = u64::from_le_bytes(f.payload[..8].try_into().unwrap());
            lat.push(reader_base.elapsed().as_nanos() as u64 - sent_ns);
        }
        lat
    });
    for i in 0..frames {
        let ns = base.elapsed().as_nanos() as u64;
        let mut p = ns.to_le_bytes().to_vec();
        p.extend_from_slice(b"0123456789abcdef");
        reg.publish(&ch, TYP_MEDIA, p).unwrap();
        if i % 32 == 0 {
            tokio::task::yield_now().await;
        }
    }
    reg.unsubscribe(&ch, 1);
    let mut lat = reader.await.unwrap();
    if lat.is_empty() {
        return u64::MAX;
    }
    lat.sort_unstable();
    let idx = (lat.len() as f64 * 0.99).ceil() as usize;
    lat[idx.saturating_sub(1).min(lat.len() - 1)] / 1000
}

/// Head-of-Line: ein nie leerender Abonnent darf den schnellen NICHT
/// bremsen. Gemessen wird die Zustell-Latenz AM SCHNELLEN Abonnenten
/// (publish -> Empfang), kanalisoliert je Runde.
pub async fn hol(reg: Arc<ChannelRegistry>, round: u64, frames: u64) -> (u64, bool) {
    let ch = "folter/hol".to_string();
    reg.open(&ch).unwrap();
    let _slow = reg.subscribe(&ch, 1).unwrap();
    let fast = reg.subscribe(&ch, 2).unwrap();
    let r = reg.clone();
    let base = Instant::now();
    let reader_base = base;
    let reader = tokio::spawn(async move {
        let mut lat = Vec::new();
        while let Some(raw) = r.recv(&fast).await {
            let f = proxy_native::Frame::decode(&raw).unwrap();
            if f.payload.len() < 8 {
                continue;
            }
            let sent_ns = u64::from_le_bytes(f.payload[..8].try_into().unwrap());
            lat.push(reader_base.elapsed().as_nanos() as u64 - sent_ns);
        }
        lat
    });
    let mut ok = true;
    for i in 0..frames {
        let ns = base.elapsed().as_nanos() as u64;
        let mut p = ns.to_le_bytes().to_vec();
        p.extend_from_slice(&(i as u32).to_le_bytes());
        if reg.publish(&ch, TYP_MEDIA, p).is_err() {
            ok = false;
            break;
        }
        if i % 32 == 0 {
            tokio::task::yield_now().await;
        }
    }
    reg.unsubscribe(&ch, 2);
    let mut lat = reader.await.unwrap();
    if lat.is_empty() {
        return (u64::MAX, false);
    }
    lat.sort_unstable();
    let idx = (lat.len() as f64 * 0.99).ceil() as usize;
    let p99 = lat[idx.saturating_sub(1).min(lat.len() - 1)] / 1000;
    (p99, ok)
}

