//! S5 GESAMT-EXPORT (G12–G15): EINE API mit SELEKTION ueber die Welten.
//! Friert den WAL-Stand N ein, legt JSONL + Binaer-Blobs in einen
//! PQC-Container mit Manifest (sha256 je Datei + Hash-Kette). Secrets
//! wandern NUR als Name + versiegelte Huelle ins Manifest, nie Klartext.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use proxy_kern::ProxyError;
use serde_json::Value;

pub use crate::export_worlds::{ExportRequest, World};
use crate::export_worlds::ALL;
use crate::service::ProxyService;

impl ProxyService {
    pub async fn export_all(&self, req: &ExportRequest) -> Result<Value, ProxyError> {
        let db = req.db_id.clone().unwrap_or_else(|| "demo".to_string());
        let worlds: Vec<World> = if req.worlds.is_empty() {
            ALL.to_vec()
        } else {
            req.worlds.clone()
        };
        // FREEZE: Schreib-Reservierung auf allen beteiligten DBs blockiert
        // jeden Schreiber; DANACH WAL-Stand N lesen. Freigabe immer am Ende.
        let mut ids: Vec<String> = Vec::new();
        if worlds
            .iter()
            .any(|w| matches!(w, World::Linefs | World::Blobs | World::Flows | World::Apps))
        {
            ids.push(db.clone());
        }
        if worlds.contains(&World::Otel) {
            ids.push(self.cfg.otel_db.clone());
        }
        if worlds.contains(&World::Meta) {
            ids.push(self.cfg.meta_db.clone());
            ids.push(self.cfg.cluster_meta_db.clone());
        }
        ids.dedup();
        let mut held: Vec<String> = Vec::new();
        for id in ids {
            if held.contains(&id) {
                continue;
            }
            match self.db.reserve(&id, "export-all").await {
                Ok(_) => held.push(id),
                Err(e) => {
                    for h in &held {
                        let _ = self.db.release(h, "export-all").await;
                    }
                    return Err(ProxyError::Db(format!("Freeze-Reservierung {id}: {e}")));
                }
            }
        }
        let freeze = self.db.status(None).await.unwrap_or(Value::Null);
        let out = self.export_collect(req, &worlds, &db, freeze).await;
        for h in &held {
            let _ = self.db.release(h, "export-all").await;
        }
        out
    }

}

/// Oeffnet einen Export-Container (Tests/CLI/Import): Manifest + Verzeichnis.
pub fn open_export(
    container: &[u8],
    passwort: &str,
) -> Result<(Value, Vec<(String, Vec<u8>)>), String> {
    let mode = z8run_core::dbnode::OpenBox::Password { passwort };
    z8run_core::dbnode::open_export_container(container, mode).map_err(|e| e.to_string())
}

/// Hilfsfunktion fuer Clients, die nur den Container weitergeben.
pub fn decode_container(b64: &str) -> Result<Vec<u8>, String> {
    B64.decode(b64).map_err(|e| e.to_string())
}
