//! Eigenes Ausgangspuffer je Abonnent (G5). `push` sperrt nur kurz und wirft
//! bei vollem Puffer die AELTESTEN Frames weg — kein await, kein Blockieren.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub struct Subscriber {
    pub channel: String,
    pub socket_id: u64,
    pub(crate) queue: Mutex<SubState>,
    pub(crate) notify: tokio::sync::Notify,
}

pub(crate) struct SubState {
    pub(crate) ring: VecDeque<Arc<[u8]>>,
    pub(crate) overflows: u64,
    pub(crate) closed: bool,
}

impl Subscriber {
    pub fn channel(&self) -> &str {
        &self.channel
    }

    pub fn overflows(&self) -> u64 {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).overflows
    }

    pub fn depth(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).ring.len()
    }

    pub fn close(&self) {
        let mut st = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        st.closed = true;
        drop(st);
        self.notify.notify_waiters();
    }

    pub(crate) async fn recv(&self) -> Option<Arc<[u8]>> {
        loop {
            let notified = self.notify.notified();
            {
                let mut st = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(frame) = st.ring.pop_front() {
                    return Some(frame);
                }
                if st.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    pub(crate) fn push(&self, frame: Arc<[u8]>, cap: usize) -> bool {
        let mut st = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if st.closed {
            return false;
        }
        if st.ring.len() >= cap.max(1) {
            st.ring.pop_front();
            st.overflows += 1;
        }
        st.ring.push_back(frame);
        drop(st);
        self.notify.notify_one();
        true
    }
}
