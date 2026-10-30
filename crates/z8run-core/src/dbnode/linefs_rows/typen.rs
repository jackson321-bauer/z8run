//! Transport-Typen der Zeilen-Welt (Port des CE-Kerns, ohne DB-Zugriff).

use super::zeilen::Ende;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Eine geplante SQL-Aktion (WAL-fähig: sql + JSON-Parameter).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Aktion {
    pub sql: String,
    pub params: Vec<Value>,
}

/// Zeile im Sitzungs-/Ziel-Zustand: schluessel None = neue Zeile.
#[derive(Clone, Debug)]
pub struct ZeileStand {
    pub schluessel: Option<i64>,
    pub inhalt: String,
    pub ende: Ende,
    pub geloescht: bool,
}

impl ZeileStand {
    pub fn neu(inhalt: &str, ende: Ende) -> Self {
        ZeileStand {
            schluessel: None,
            inhalt: inhalt.to_string(),
            ende,
            geloescht: false,
        }
    }
}

/// StandZeile aus der DB (fuer den Diff).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IstZeile {
    pub schluessel: i64,
    pub nr: i64,
    pub inhalt: String,
    pub ende: i64,
    pub geloescht: bool,
}

/// Datei-Kopf (Registry-Zeile) als Planungs-Eingabe.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DateiKopf {
    pub name: String,
    pub art: String,
    pub fassung: i64,
    pub hashkette: String,
    pub ordner_id: i64,
}

/// Epochenzeile (Transport) fuer Zeitmaschine + Zeilen-Historie.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpocheRoh {
    pub schluessel: i64,
    pub fassung: i64,
    pub nr: i64,
    pub inhalt: String,
    pub ende: i64,
    pub geloescht: bool,
}

/// Geschichts-Zeile (Transport) fuer die Ketten-Verifikation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KettenZeile {
    pub seite: i64,
    pub schluessel: i64,
    pub nr: i64,
    pub seg: i64,
    pub inhalt: String,
    pub ende: i64,
    pub fassung: i64,
    pub geloescht: bool,
    pub ts: String,
    pub urheber: String,
    pub vor_hash: String,
    pub hash: String,
}

pub fn sha256_hex(daten: &[u8]) -> String {
    hex::encode(Sha256::digest(daten))
}

#[allow(clippy::too_many_arguments)]
pub fn zeilen_hash(
    vor: &str,
    datei_id: i64,
    seite: i64,
    schluessel: i64,
    nr: i64,
    seg: i64,
    inhalt: &str,
    ende: Ende,
    geloescht: bool,
    fassung: i64,
    ts: &str,
    urheber: &str,
) -> String {
    let mut stoff = Vec::new();
    stoff.extend_from_slice(vor.as_bytes());
    stoff.extend_from_slice(b"|");
    stoff.extend_from_slice(&datei_id.to_le_bytes());
    stoff.extend_from_slice(&seite.to_le_bytes());
    stoff.extend_from_slice(&schluessel.to_le_bytes());
    stoff.extend_from_slice(&nr.to_le_bytes());
    stoff.extend_from_slice(&seg.to_le_bytes());
    stoff.extend_from_slice(inhalt.as_bytes());
    stoff.extend_from_slice(&[ende.code() as u8, geloescht as u8]);
    stoff.extend_from_slice(&fassung.to_le_bytes());
    stoff.extend_from_slice(ts.as_bytes());
    stoff.extend_from_slice(urheber.as_bytes());
    sha256_hex(&stoff)
}
