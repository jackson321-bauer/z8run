//! AUFNAHME (G8): derselbe Kanal laeuft parallel als Blob-Session.
//! Chunks werden versiegelt live angehaengt; der Fan-out wird nie blockiert
//! (unbounded Queue, eigener Worker). Es gibt EINEN Mitschnitt, keinen
//! zweiten Stream.

use std::sync::{Arc, Mutex};

use proxy_kern::{DbPort, ProxyError};
use serde_json::Value;
use tokio::sync::{mpsc, Notify};

use crate::channel::FrameTap;

enum Msg {
    Frame(Vec<u8>),
    Finish,
}

struct State {
    manifest: Option<Result<Value, String>>,
    finished: bool,
}

pub struct Recording {
    tx: mpsc::UnboundedSender<Msg>,
    state: Mutex<State>,
    notify: Notify,
}

impl Recording {
    pub fn start(
        db: Arc<dyn DbPort>,
        db_id: String,
        session_id: String,
        owner: String,
        mime: String,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let rec = Arc::new(Self {
            tx,
            state: Mutex::new(State { manifest: None, finished: false }),
            notify: Notify::new(),
        });
        let worker = rec.clone();
        tokio::spawn(async move {
            worker.run(rx, db, db_id, session_id, owner, mime).await;
        });
        rec
    }

    fn complete(&self, res: Result<Value, String>) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.manifest = Some(res);
        st.finished = true;
        drop(st);
        self.notify.notify_waiters();
    }

    fn push_frame(&self, data: &[u8]) {
        let _ = self.tx.send(Msg::Frame(data.to_vec()));
    }

    pub fn finish(&self) {
        let _ = self.tx.send(Msg::Finish);
    }

    pub async fn wait_finished(&self) -> Result<Value, String> {
        loop {
            let notified = self.notify.notified();
            {
                let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if st.finished {
                    return st.manifest.clone().unwrap_or_else(|| Err("kein Manifest".into()));
                }
            }
            notified.await;
        }
    }

    async fn run(
        &self,
        mut rx: mpsc::UnboundedReceiver<Msg>,
        db: Arc<dyn DbPort>,
        db_id: String,
        session_id: String,
        owner: String,
        mime: String,
    ) {
        let begin = match db.blob_session_begin(&db_id, &session_id, &owner, &mime).await {
            Ok(v) => v,
            Err(e) => {
                self.complete(Err(e.to_string()));
                return;
            }
        };
        let sid = begin.get("session_id").and_then(Value::as_str).unwrap_or("").to_string();
        if sid.is_empty() {
            self.complete(Err("Blob-Session ohne session_id".into()));
            return;
        }
        while let Some(msg) = rx.recv().await {
            match msg {
                Msg::Frame(data) => {
                    if let Err(e) = db.blob_session_append(&db_id, &session_id, &sid, &data, 0).await {
                        self.complete(Err(e.to_string()));
                        return;
                    }
                }
                Msg::Finish => {
                    let out = db
                        .blob_session_finish(&db_id, &session_id, &sid)
                        .await
                        .map_err(|e| e.to_string());
                    self.complete(out);
                    return;
                }
            }
        }
        let out = db
            .blob_session_finish(&db_id, &session_id, &sid)
            .await
            .map_err(|e| e.to_string());
        self.complete(out);
    }
}

impl FrameTap for Recording {
    fn on_frame(&self, _seq: u64, _typ: u8, payload: &[u8]) {
        self.push_frame(payload);
    }
}

/// Liest die Aufnahme als Kanal-Wiedergabe (verschluesselte Blobs werden
/// beim Lesen entschluesselt, nie als Klartext gespeichert).
pub async fn read_recording(
    db: &dyn DbPort,
    db_id: &str,
    sid: &str,
) -> Result<Vec<u8>, ProxyError> {
    db.blob_session_get(db_id, "playback", sid).await
}
