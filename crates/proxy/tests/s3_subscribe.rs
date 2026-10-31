//! S3: Subscribe/Push-Naht — Fan-out, Filter, Push-Latenz, Cursor-Resume.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use proxy_native::{Event, EventHub, Filter, Sink};
use serde_json::json;

struct Counter {
    seqs: Mutex<Vec<u64>>,
    max_latency: Mutex<Duration>,
    started: Mutex<Option<Instant>>,
    crash_on: Option<u64>,
}

impl Counter {
    fn new(crash_on: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            seqs: Mutex::new(Vec::new()),
            max_latency: Mutex::new(Duration::ZERO),
            started: Mutex::new(None),
            crash_on,
        })
    }
    fn seqs(&self) -> Vec<u64> {
        self.seqs.lock().unwrap().clone()
    }
    fn mark(&self) {
        *self.started.lock().unwrap() = Some(Instant::now());
    }
}

#[async_trait]
impl Sink for Counter {
    async fn deliver(&self, event: &Event) -> bool {
        if let Some(start) = *self.started.lock().unwrap() {
            let d = start.elapsed();
            let mut m = self.max_latency.lock().unwrap();
            if d > *m {
                *m = d;
            }
        }
        if Some(event.seq) == self.crash_on {
            return false;
        }
        self.seqs.lock().unwrap().push(event.seq);
        true
    }
}

#[tokio::test]
async fn fanout_filter_latenz_und_cursor() {
    let hub = EventHub::new(1000);
    let a = Counter::new(None);
    let b = Counter::new(None);
    hub.subscribe(Filter::all(), a.clone());
    hub.subscribe(Filter::all(), b.clone());
    assert_eq!(hub.subscriber_count(), 2);

    // Latenz Aktion -> Senke (lokal, messbar).
    a.mark();
    for i in 0..50 {
        hub.publish("c-a", "proxy", "meta:login", "trace", json!({"i": i})).await;
    }
    let lat = *a.max_latency.lock().unwrap();
    println!("PUSH_LATENZ max={:?}", lat);
    assert!(lat < Duration::from_millis(10), "Push-Latenz {lat:?} >= 10 ms");
    assert_eq!(a.seqs().len(), 50, "Abonnent A unvollstaendig");
    assert_eq!(b.seqs().len(), 50, "Abonnent B unvollstaendig (Fan-out)");

    // Filter: Cluster A darf B-Ereignisse nicht sehen.
    let only_a = Counter::new(None);
    hub.subscribe(
        Filter { cluster: Some("c-a".into()), ..Filter::all() },
        only_a.clone(),
    );
    hub.publish("c-b", "proxy", "meta:login", "t", json!({})).await;
    hub.publish("c-a", "proxy", "meta:login", "t", json!({})).await;
    assert_eq!(only_a.seqs(), vec![52], "Filter Cluster greift nicht");

    // Absturz: Senke faellt bei seq 53 aus, Cursor-Wiederaufnahme holt nach.
    let crash = Counter::new(Some(53));
    hub.subscribe(Filter::all(), crash.clone());
    for _ in 0..3 {
        hub.publish("c-a", "proxy", "meta:x", "trace-resume", json!({})).await;
    }
    let seen = crash.seqs();
    assert!(!seen.contains(&53), "Absturz-Sink hat 53 trotzdem gesehen");
    let cursor = 52;
    let missed = hub.since(cursor);
    assert!(missed.iter().any(|e| e.seq == 53), "Cursor holt 53 nicht nach");
    // Wiederaufnahme (Restart): alle fehlenden sequenziell zustellen.
    let replay = Counter::new(None);
    for e in &missed {
        replay.deliver(e).await;
    }
    let restored = replay.seqs();
    assert_eq!(restored, vec![53, 54, 55], "Cursor-Wiederaufnahme unvollstaendig");
    println!("PUSH_CURSOR nachgeholt={restored:?} dropped={}", hub.dropped());
}
