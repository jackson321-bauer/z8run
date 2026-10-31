//! S1: Kanal-Kern — Claim-Streit, Reconnect-Erbe, Fan-out, Overflow,
//! Head-of-Line-Isolation, Frame-Roundtrip.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use proxy_kern::{Clock, ProxyError};
use proxy_native::channel::{valid_channel, ChannelConfig, ChannelRegistry};
use proxy_native::frame::{Frame, HEADER_LEN, TYP_MEDIA};

struct ManualClock(AtomicU64);

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl ManualClock {
    fn new(t: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(t)))
    }
    fn set(&self, t: u64) {
        self.0.store(t, Ordering::Relaxed);
    }
}

fn registry(cfg: ChannelConfig, clock: Arc<ManualClock>) -> ChannelRegistry {
    ChannelRegistry::new(cfg, clock)
}

#[tokio::test]
async fn claim_streit_reconnect_grace_release() {
    let clock = ManualClock::new(1_000);
    let reg = registry(ChannelConfig { claim_grace_ms: 5_000, ..Default::default() }, clock.clone());
    let ch = "app/telefon-a";

    let a = reg.claim(ch, "ident-a", 1).unwrap();
    assert_eq!(a.identity, "ident-a");
    // Zweite Identitaet bei aktivem Claim: abgewiesen.
    assert!(matches!(reg.claim(ch, "ident-b", 2), Err(ProxyError::Stream(_))));

    // Reconnect derselben Identitaet erbt den Claim im Grace-Fenster.
    reg.disconnect(ch, 1);
    clock.set(2_000);
    assert!(reg.claim(ch, "ident-a", 3).is_ok());
    assert_eq!(reg.stream_id(ch), Some(a.stream_id));

    // Fremde Identitaet im Grace-Fenster: abgewiesen.
    reg.disconnect(ch, 3);
    clock.set(2_500);
    assert!(matches!(reg.claim(ch, "ident-b", 4), Err(ProxyError::Stream(_))));

    // Nach Ablauf des Grace-Fensters darf die fremde Identitaet uebernehmen.
    clock.set(8_000);
    assert!(reg.claim(ch, "ident-b", 5).is_ok());

    // Explizite Freigabe gibt den Kanal sofort fuer den Naechsten frei.
    reg.release(ch, "ident-b").unwrap();
    assert!(reg.claim(ch, "ident-c", 6).is_ok());
    println!("CLAIM streit=ok reconnect=ok grace=ok release=ok");
}

#[tokio::test]
async fn fanout_drei_abonnenten_eigenes_exemplar_gleiche_sequenz() {
    let clock = ManualClock::new(1);
    let reg = registry(ChannelConfig::default(), clock);
    let ch = "app/kanal";
    reg.open(ch).unwrap();
    let subs: Vec<_> = (0..3).map(|s| reg.subscribe(ch, s).unwrap()).collect();
    assert_eq!(reg.subscriber_count(ch), 3);

    for i in 0..20u32 {
        let out = reg.publish(ch, TYP_MEDIA, format!("payload-{i}").into_bytes()).unwrap();
        assert_eq!(out.delivered, 3);
        assert_eq!(out.seq, i as u64);
    }
    let mut seen = Vec::new();
    for sub in &subs {
        let mut seqs = Vec::new();
        let mut bytes = Vec::new();
        while let Some(raw) = reg.recv(sub).await {
            let f = Frame::decode(&raw).unwrap();
            seqs.push(f.seq);
            bytes.push(f.payload);
            if seqs.len() == 20 {
                break;
            }
        }
        assert_eq!(seqs, (0..20u64).collect::<Vec<_>>(), "Sequenz nicht identisch");
        assert_eq!(bytes[0], b"payload-0".to_vec());
        seen.push(seqs);
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]), "Fan-out-Exemplare verschieden");
    println!("FANOUT abonnenten=3 frames=20 sequenz=identisch");
}

#[tokio::test]
async fn overflow_wirft_aelteste_und_meldet_meta() {
    let clock = ManualClock::new(1);
    let cfg = ChannelConfig { sub_queue: 3, ..Default::default() };
    let reg = registry(cfg, clock);
    let seen: Arc<Mutex<Vec<(String, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink_seen = seen.clone();
    reg.set_overflow_sink(Arc::new(move |channel, dropped| {
        sink_seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((channel.to_string(), dropped));
    }));
    let ch = "app/overflow";
    let sub = reg.subscribe(ch, 1).unwrap();

    let mut overflows = 0u64;
    for i in 0..10u32 {
        overflows += reg.publish(ch, TYP_MEDIA, format!("{i}").into_bytes()).unwrap().overflowed;
    }
    assert!(overflows >= 7, "Overflow nicht gezaehlt: {overflows}");
    assert_eq!(sub.overflows(), overflows);
    assert!(sub.depth() <= 3);

    // Es bleiben die JUENGSTEN Frames (Live vor Vollstaendigkeit).
    let mut kept = Vec::new();
    for _ in 0..3 {
        let f = Frame::decode(&reg.recv(&sub).await.unwrap()).unwrap();
        kept.push(String::from_utf8(f.payload).unwrap());
    }
    assert_eq!(kept, vec!["7", "8", "9"]);
    // ECHTES Meta-Ereignis stream_overflow wurde zentral gemeldet.
    let events = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let reported: u64 = events.iter().map(|(_, n)| *n).sum();
    assert!(reported >= 7, "stream_overflow nicht gemeldet: {events:?}");
    assert!(events.iter().all(|(c, _)| c == ch));
    println!(
        "OVERFLOW verworfen={overflows} behalten={kept:?} meta_events={} gemeldet={reported}",
        events.len()
    );
}

#[tokio::test]
async fn langsamer_abonnent_blockiert_andere_nicht() {
    let clock = ManualClock::new(1);
    let cfg = ChannelConfig { sub_queue: 2, ..Default::default() };
    let reg = registry(cfg, clock);
    let ch = "app/hol";
    let slow = reg.subscribe(ch, 1).unwrap();
    let fast = reg.subscribe(ch, 2).unwrap();

    let start = Instant::now();
    let mut fast_seqs = Vec::new();
    for i in 0..5_000u32 {
        reg.publish(ch, TYP_MEDIA, i.to_be_bytes().to_vec()).unwrap();
        let f = Frame::decode(&reg.recv(&fast).await.unwrap()).unwrap();
        fast_seqs.push(f.seq);
    }
    let elapsed = start.elapsed();
    assert_eq!(fast_seqs.len(), 5_000);
    assert_eq!(fast_seqs.first(), Some(&0));
    assert_eq!(fast_seqs.last(), Some(&4_999));
    assert!(elapsed < Duration::from_secs(5), "Publish blockiert: {elapsed:?}");
    assert!(slow.overflows() > 0);
    println!("HOL publish_5000={elapsed:?} schnell=vollstaendig langsam_overflow={}", slow.overflows());
}

#[test]
fn frame_roundtrip_binaer_byte_genau() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let f = Frame::with_flags(TYP_MEDIA, 0xA5, 42, 7, payload.clone()).unwrap();
    let bytes = f.encode().unwrap();
    assert_eq!(bytes.len(), HEADER_LEN + payload.len());
    // G2: Header EXAKT 16 B, little endian, flags an Byte 3.
    assert_eq!(&bytes[0..2], &0x5A38u16.to_le_bytes());
    assert_eq!(bytes[2], TYP_MEDIA);
    assert_eq!(bytes[3], 0xA5);
    assert_eq!(&bytes[4..8], &42u32.to_le_bytes());
    assert_eq!(&bytes[8..16], &7u64.to_le_bytes());
    let back = Frame::decode(&bytes).unwrap();
    assert_eq!(back.typ, TYP_MEDIA);
    assert_eq!(back.flags, 0xA5);
    assert_eq!(back.stream_id, 42);
    assert_eq!(back.seq, 7);
    assert_eq!(back.len(), 4096);
    assert_eq!(back.payload, payload);

    // Rohbytes sind unveraendert hinter dem Header.
    assert_eq!(&bytes[HEADER_LEN..], payload.as_slice());
    assert!(Frame::decode(&bytes[..4]).is_err());
    let mut kaputt = bytes.clone();
    kaputt[0] = 0;
    assert!(Frame::decode(&kaputt).is_err());
    println!("FRAME roundtrip bytes={} magic=0x5A38", bytes.len());
}

#[test]
fn kanalnamen_und_limits() {
    assert!(valid_channel("app/kanal"));
    assert!(valid_channel("app/kanal/session-1"));
    assert!(!valid_channel("app"));
    assert!(!valid_channel("app//x"));
    assert!(!valid_channel("app/kanal/x/y"));
    assert!(!valid_channel("app/ka nal"));
    assert_eq!(proxy_native::channel::CHANNELS_PER_SESSION, 64);
    assert_eq!(proxy_native::channel::SUBSCRIBERS_PER_CHANNEL, 32);
}
