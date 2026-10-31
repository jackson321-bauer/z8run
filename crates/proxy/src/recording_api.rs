//! Aufnahme-API: Kanal parallel als Blob-Session versiegeln + Wiedergabe
//! ueber dieselbe Kanal-Welt (G8).

use std::sync::Arc;
use std::time::Duration;

use proxy_kern::ProxyError;
use serde_json::Value;

use crate::frame::TYP_MEDIA;
use crate::recording::{read_recording, Recording};
use crate::service::ProxyService;

impl ProxyService {
    pub async fn recording_start(
        &self,
        db_id: &str,
        channel: &str,
        owner: &str,
        mime: &str,
    ) -> Result<Arc<Recording>, ProxyError> {
        let rec = Recording::start(
            self.db.clone(),
            db_id.to_string(),
            format!("record:{channel}"),
            owner.to_string(),
            mime.to_string(),
        );
        self.streams.set_tap(channel, Some(rec.clone()))?;
        self.recordings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(channel.to_string(), rec.clone());
        self.record_meta(
            "app",
            proxy_kern::meta::EventKind::AppCall,
            channel,
            "",
            &self.cfg.cluster_id,
            "ok",
            "recording_start",
        )
        .await;
        Ok(rec)
    }

    pub async fn recording_stop(&self, channel: &str) -> Result<Value, ProxyError> {
        let rec = self
            .recordings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(channel)
            .ok_or_else(|| ProxyError::NotFound(format!("Aufnahme {channel}")))?;
        self.streams.set_tap(channel, None)?;
        rec.finish();
        let manifest = tokio::time::timeout(Duration::from_secs(60), rec.wait_finished())
            .await
            .map_err(|_| ProxyError::Internal("Aufnahme-Timeout".into()))?
            .map_err(ProxyError::Internal)?;
        self.record_meta(
            "app",
            proxy_kern::meta::EventKind::AppCall,
            channel,
            "",
            &self.cfg.cluster_id,
            "ok",
            "recording_stop",
        )
        .await;
        Ok(manifest)
    }

    /// Wiedergabe: Aufnahme-Bytes werden als normale Kanal-Frames publiziert.
    pub async fn playback_recording(
        &self,
        db_id: &str,
        sid: &str,
        channel: &str,
        chunk_size: usize,
    ) -> Result<usize, ProxyError> {
        let bytes = read_recording(self.db.as_ref(), db_id, sid).await?;
        let mut frames = 0;
        for chunk in bytes.chunks(chunk_size.max(1)) {
            self.streams.publish(channel, TYP_MEDIA, chunk.to_vec())?;
            frames += 1;
        }
        Ok(frames)
    }
}
