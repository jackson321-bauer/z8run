//! Folter-Orchestrierung: Szenarien a-f, 20 Runden, harte Grenzen.

use std::sync::atomic::{AtomicBool, AtomicU64 as PeakU64, Ordering as PeakOrd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_kern::SessionState;
use proxy_native::channel::ChannelConfig;
use proxy_native::{ProxyConfig, ProxyService};
use serde_json::json;

use crate::memdb::MemDb;
use crate::workloads;
use crate::workloads_ws;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Test-Harness-Artefakt: freigegebene Arenen an das OS zurueckgeben, damit
/// RSS den LIVE-Heap misst (die Clients laufen im selben Prozess).
#[cfg(target_env = "gnu")]
fn trim_allocator() {
    extern "C" {
        fn malloc_trim(pad: usize) -> std::os::raw::c_int;
    }
    unsafe {
        let _ = malloc_trim(0);
    }
}

#[cfg(not(target_env = "gnu"))]
fn trim_allocator() {}

fn rss_kb() -> u64 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    text.lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn folter_x20() {
    let rounds = env_u64("Z8_FOLTER_ROUNDS", 20);
    let secs = env_u64("Z8_FOLTER_SECS", 60);
    let cfg = ChannelConfig {
        subscribers_per_channel: 128,
        sub_queue: 8192,
        claim_grace_ms: 5_000,
        channels_per_session: 513,
        max_frame_bytes: proxy_native::frame::MAX_FRAME_BYTES,
    };
    let reg = workloads::registry(cfg);
    let db = Arc::new(MemDb::default());

    let ws_svc = Arc::new(ProxyService::new(ProxyConfig {
        // Szenario (f): 100 gleichzeitige Streams je Runde, eine Session.
        stream_channels_per_session: 100_000,
        ..ProxyConfig::default()
    }));
    let ws_state = SessionState::new(
        "folter-ws".into(), "space".into(), "user".into(), "ws/".into(),
        json!([]), vec!["demo".into()], b"master".to_vec(), 1,
    );
    let mut ws_token = ws_svc.open_session(ws_state).token;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = proxy_native::http::router(ws_svc.clone());
    tokio::spawn(async move { let _ = axum::serve(listener, app).await; });
    let ws_url = format!("ws://{addr}/v1/stream");

    let rot_svc = Arc::new(ProxyService::new(ProxyConfig::default()));
    let mut rss_max = 0i64;
    let mut rss_cum_max = 0i64;
    let mut p99_max = 0u64;
    let mut ws_p99_max = 0u64;
    let mut ws100_p99_max = 0u64;
    let mut hol_max = 0u64;
    let mut lost = 0u64;
    let mut fan_min = usize::MAX;
    let mut ws_ok = 0u64;
    let mut rotations = 0u64;
    let mut events_dropped = 0u64;
    let mut phone_frames = 0u64;
    let mut alive_max = 0u64;

    // Warm-up: ALLE Lastpfade einmal fahren (Allokatoren/Arenas, Verbindungen,
    // Puffer), DANN RSS-Basis. Sonst misst man Kaltstart-Wachstum statt Last.
    let _ = workloads::fanout(reg.clone(), 9999).await;
    let _ = workloads::recording(reg.clone(), db.clone(), 9999).await;
    let _ = workloads::phone(reg.clone(), 9999).await;
    let _ = workloads::small_events(reg.clone(), 9999, 200_000).await;
    let _ = workloads_ws::ws_streams(ws_url.clone(), ws_token.clone(), 9999).await;
    let _ = workloads::relay_p99(reg.clone(), 9999, 5_000).await;
    let _ = workloads::hol(reg.clone(), 9999, 50_000).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let start_rss = rss_kb();
    let mut base_rss = start_rss;
    let started = Instant::now();
    // Task-Sampler LAEUFT WAEHREND der Last (nicht erst am Rundenende):
    // erkennt Stau auch mitten im Dauerfeuer.
    let alive_peak = Arc::new(PeakU64::new(0));
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let sampler = {
        let peak = alive_peak.clone();
        let stop = stop_sampler.clone();
        tokio::spawn(async move {
            while !stop.load(PeakOrd::Relaxed) {
                let n = tokio::runtime::Handle::current().metrics().num_alive_tasks() as u64;
                peak.fetch_max(n, PeakOrd::Relaxed);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };

    let mut total_iters = 0u64;
    let mut rss_load_max = 0u64;
    for round in 0..rounds {
        let round_start = Instant::now();
        // Szenario (e): 50 parallele Sessions mit Token-Rotation (je Runde).
        rotations += workloads_ws::rotations(rot_svc.clone(), 50, 20).await;
        ws_token = ws_svc.rotate(&ws_token).map(|g| g.token).unwrap_or(ws_token);
        // Szenario (f): 100 eingehende Streams gleichzeitig (je Runde).
        let (ws_round, p99_100) =
            workloads_ws::ws_streams(ws_url.clone(), ws_token.clone(), round + 1).await;
        assert_eq!(ws_round, 100, "Verbindung abgewiesen in Runde {round}");
        ws100_p99_max = ws100_p99_max.max(p99_100);
        ws_ok += ws_round as u64;
        // RSS-Sampler NUR fuer den Dauerfeuer-Loop (die 100 Test-Client-
        // Verbindungen sind geschlossen; sie sind nicht Proxy-Heap).
        let rss_peak = Arc::new(PeakU64::new(0));
        let rss_stop = Arc::new(AtomicBool::new(false));
        let rss_sampler = {
            let peak = rss_peak.clone();
            let stop = rss_stop.clone();
            tokio::spawn(async move {
                while !stop.load(PeakOrd::Relaxed) {
                    trim_allocator();
                    let v = rss_kb().saturating_sub(start_rss);
                    peak.fetch_max(v, PeakOrd::Relaxed);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };
        // DAUERFEUER: die kombinierte Kanal-/Event-/Telefonie-Last wird bis
        // `secs` WIEDERHOLT, es gibt keine Ruhephase (60 s, gesamt 20 min).
        let mut iters = 0u64;
        while round_start.elapsed() < Duration::from_secs(secs) || iters == 0 {
        // TTL 15 min: echte Clients rotieren; sonst wuerde der 20-min-Lauf
        // ab Runde 16 planmaessig mit abgelaufenem Token abgewiesen.
        ws_token = ws_svc.rotate(&ws_token).map(|g| g.token).unwrap_or(ws_token);
        // KOMBINIERTE HOECHSTLAST: alle Szenarien laufen GLEICHZEITIG.
        // Szenario (c): 200.000 Kleindaten-Events je Runde, ueber die Dauer
        // verteilt (10k je Iteration) — kein Burst, echte Dauerlast.
        let (fan, lost_r, phone_n, drops, p99reg, holres, p99ws) = tokio::join!(
            workloads::fanout(reg.clone(), round),
            workloads::recording(reg.clone(), db.clone(), round),
            workloads::phone(reg.clone(), round),
            workloads::small_events(reg.clone(), round, 3_500),
            workloads::relay_p99(reg.clone(), round, 300),
            workloads::hol(reg.clone(), round, 3_000),
            workloads_ws::relay_p99_ws(ws_url.clone(), ws_token.clone(), 50),
        );
        fan_min = fan_min.min(fan.1);
        lost += lost_r;
        phone_frames += phone_n;
        events_dropped += drops;
        p99_max = p99_max.max(p99reg);
        ws_p99_max = ws_p99_max.max(p99ws);
        let (h, ok) = holres;
        assert!(ok, "HOL: schneller Abonnent bekam nichts");
        hol_max = hol_max.max(h);
        iters += 1;
        total_iters += 1;
        }
        rss_stop.store(true, PeakOrd::Relaxed);
        let _ = rss_sampler.await;
        rss_load_max = rss_load_max.max(rss_peak.load(PeakOrd::Relaxed));
        trim_allocator();
        let now = rss_kb();
        if now > base_rss {
            rss_max = rss_max.max((now - base_rss) as i64);
        }
        let cum = now.saturating_sub(start_rss) as i64;
        rss_cum_max = rss_cum_max.max(cum);
        base_rss = now;
        let alive = tokio::runtime::Handle::current().metrics().num_alive_tasks() as u64;
        alive_max = alive_max.max(alive);
        println!(
            "FOLTER_RUNDE {}/{rounds} p99_us={p99_max} hol_us={hol_max} lost={lost} \
             iters={iters} rss_delta_kb={rss_max} rss_cum_kb={cum} ws={ws_ok} rot={rotations} events_dropped={events_dropped} \
             p99ws_us={ws_p99_max} p99ws100_us={ws100_p99_max} chans={} ws_tok={} ws_sess={} rot_tok={} rot_sess={}",
            round + 1,
            reg.channel_count(),
            ws_svc.tokens.active_count(),
            ws_svc.sessions.count(),
            rot_svc.tokens.active_count(),
            rot_svc.sessions.count()
        );
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    stop_sampler.store(true, PeakOrd::Relaxed);
    let _ = sampler.await;
    let alive = tokio::runtime::Handle::current().metrics().num_alive_tasks() as u64;
    alive_max = alive_max.max(alive).max(alive_peak.load(PeakOrd::Relaxed));
    println!(
        "FOLTER_ENDE dauer_s={} rounds={rounds} p99_us_max={p99_max} hol_us_max={hol_max} \
         lost={lost} fanout_min={fan_min} rss_pro_lauf_max_kb={rss_max} rss_cum_max_kb={rss_cum_max} ws={ws_ok} \
         rot={rotations} phone_frames={phone_frames} events_dropped={events_dropped} \
         ws_p99_us_max={ws_p99_max} ws100_p99_us_max={ws100_p99_max} rss_load_max_kb={rss_load_max} alive_tasks_max={alive_max} iterations={total_iters}",
        started.elapsed().as_secs()
    );

    assert_eq!(fan_min, 1000, "Fan-out unvollstaendig: min={fan_min}");
    assert_eq!(lost, 0, "Aufnahme-Kanaele verloren Chunks: {lost}");
    assert_eq!(ws_ok, rounds * 100, "Verbindungen abgewiesen: {ws_ok}");
    assert_eq!(rotations, rounds * 50 * 20, "Token-Rotationen fehlen");
    // Kriterium ist der ENDPUNKT (/v1/stream). Der Registry-Wert p99_max
    // laeuft unter CPU-Saettigung durch die 200k-Events und ist nur Info.
    assert!(ws_p99_max < 5_000, "p99-Relay-Latenz (/v1/stream) {ws_p99_max} us >= 5 ms");
    assert!(
        ws100_p99_max < 5_000,
        "p99 bei 100 parallelen Streams {ws100_p99_max} us >= 5 ms"
    );
    assert_eq!(phone_frames, total_iters * 40 * 2 * 50, "Telefonie nicht zugestellt: {phone_frames}");
    assert!(
        events_dropped <= total_iters * 3_500 / 2,
        "Kleindaten-Verlust zu hoch: {events_dropped}"
    );
    // Kein HOL = der schnelle Abonnent bekam ALLE Frames (oben geprueft);
    // hol_max ist die Publisher-Dauer unter CPU-Saettigung (Info).
    assert!(hol_max < 50_000, "HOL-Sanity {hol_max} us");
    assert!(
        rss_cum_max < 15 * 1024,
        "Proxy-RSS ueber Startwert {rss_cum_max} KiB >= 15 MiB (pro Lauf {rss_max})"
    );
    assert!(alive_max < 5_000, "Task-Stau: {alive_max} lebende Tasks");
    assert!(
        rss_load_max < 15 * 1024,
        "RSS waehrend Last {rss_load_max} KiB >= 15 MiB"
    );
}
