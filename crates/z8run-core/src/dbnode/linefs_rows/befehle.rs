//! Befehls-Matrix der Zeilen-Welt (DbNodeCommand-Erweiterung).
//!
//! Jede Zeile der Matrix aus docs/linefs-de.md ist als Aktion vorhanden;
//! Binär-Zeilen laufen einheitlich ueber linefs_blobs (kein binaer_s3).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinefsRequest {
    pub db_id: String,
    pub session_id: String,
    pub aktion: LinefsAktion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum LinefsAktion {
    // --- Text-/Zeilen-Welt (Matrix: anlegen .. kette_pruefen) ---
    LinefsAnlegen {
        name: String,
        #[serde(default)]
        art: String,
        #[serde(default)]
        text: String,
        #[serde(default)]
        urheber: String,
        #[serde(default)]
        ordner_id: Option<i64>,
    },
    LinefsOeffnen {
        pfad: String,
    },
    LinefsLesen {
        #[serde(default)]
        pfad: String,
        #[serde(default)]
        von: Option<i64>,
        #[serde(default)]
        bis: Option<i64>,
    },
    LinefsZeileSetzen {
        nr: i64,
        inhalt: String,
    },
    LinefsEinfuegen {
        nr: i64,
        inhalt: String,
    },
    LinefsZeileLoeschen {
        nr: i64,
    },
    LinefsSuchen {
        muster: String,
        #[serde(default)]
        pfad: String,
    },
    LinefsErsetzen {
        suche: String,
        ersatz: String,
    },
    LinefsSpeichern,
    LinefsSchliessen,
    LinefsRendere {
        pfad: String,
    },
    LinefsSeiten {
        pfad: String,
    },
    LinefsHistorie {
        #[serde(default)]
        pfad: String,
        #[serde(default)]
        nr: i64,
        /// Optional direkter Zeilen-Schluessel (auch fuer Grabmaele).
        #[serde(default)]
        schluessel: Option<i64>,
    },
    LinefsStandZuZeitpunkt {
        pfad: String,
        fassung: i64,
    },
    LinefsUmbenennen {
        pfad: String,
        neu: String,
    },
    LinefsKettePruefen {
        pfad: String,
    },
    LinefsRenderFuerProzess {
        pfad: String,
        prozess_id: String,
    },
    LinefsProzessEnde {
        prozess_id: String,
    },

    // --- Binär-Zeilen der Matrix (einheitlich linefs_blobs) ---
    LinefsBinaerHochladen {
        name: String,
        #[serde(default)]
        mime: String,
        #[serde(default)]
        datei_pfad: Option<String>,
        #[serde(default)]
        bytes_b64: Option<String>,
        #[serde(default)]
        owner: String,
    },
    LinefsBinaerZeigen {
        #[serde(default)]
        blob_id: Option<String>,
    },
    LinefsBinaerHolen {
        blob_id: String,
        #[serde(default)]
        ziel_pfad: Option<String>,
    },
    LinefsUebergangZuBinaer {
        pfad: String,
        name: String,
        #[serde(default)]
        mime: String,
    },
    LinefsUebergangZuText {
        pfad: String,
    },

    // --- Ordner-API (S2) ---
    OrdnerAnlegen {
        #[serde(default)]
        eltern_id: i64,
        name: String,
    },
    OrdnerVerschieben {
        id: i64,
        neuer_eltern_id: i64,
    },
    OrdnerUmbenennen {
        id: i64,
        name: String,
    },
    OrdnerListen {
        #[serde(default)]
        eltern_id: i64,
    },
    OrdnerPfadAufloesen {
        pfad: String,
    },
}

impl LinefsAktion {
    /// Op-Name fuer Events/Logs (Matrix-Bezeichnung).
    pub fn op(&self) -> &'static str {
        match self {
            LinefsAktion::LinefsAnlegen { .. } => "linefs_anlegen",
            LinefsAktion::LinefsOeffnen { .. } => "linefs_oeffnen",
            LinefsAktion::LinefsLesen { .. } => "linefs_lesen",
            LinefsAktion::LinefsZeileSetzen { .. } => "linefs_zeile_setzen",
            LinefsAktion::LinefsEinfuegen { .. } => "linefs_einfuegen",
            LinefsAktion::LinefsZeileLoeschen { .. } => "linefs_zeile_loeschen",
            LinefsAktion::LinefsSuchen { .. } => "linefs_suchen",
            LinefsAktion::LinefsErsetzen { .. } => "linefs_ersetzen",
            LinefsAktion::LinefsSpeichern => "linefs_speichern",
            LinefsAktion::LinefsSchliessen => "linefs_schliessen",
            LinefsAktion::LinefsRendere { .. } => "linefs_rendere",
            LinefsAktion::LinefsSeiten { .. } => "linefs_seiten",
            LinefsAktion::LinefsHistorie { .. } => "linefs_historie",
            LinefsAktion::LinefsStandZuZeitpunkt { .. } => "linefs_stand_zu_zeitpunkt",
            LinefsAktion::LinefsUmbenennen { .. } => "linefs_umbenennen",
            LinefsAktion::LinefsKettePruefen { .. } => "linefs_kette_pruefen",
            LinefsAktion::LinefsRenderFuerProzess { .. } => "linefs_render_fuer_prozess",
            LinefsAktion::LinefsProzessEnde { .. } => "linefs_prozess_ende",
            LinefsAktion::LinefsBinaerHochladen { .. } => "binaer_hochladen",
            LinefsAktion::LinefsBinaerZeigen { .. } => "binaer_zeigen",
            LinefsAktion::LinefsBinaerHolen { .. } => "binaer_holen",
            LinefsAktion::LinefsUebergangZuBinaer { .. } => "uebergang_zu_binaer",
            LinefsAktion::LinefsUebergangZuText { .. } => "uebergang_zu_text",
            LinefsAktion::OrdnerAnlegen { .. } => "ordner_anlegen",
            LinefsAktion::OrdnerVerschieben { .. } => "ordner_verschieben",
            LinefsAktion::OrdnerUmbenennen { .. } => "ordner_umbenennen",
            LinefsAktion::OrdnerListen { .. } => "ordner_listen",
            LinefsAktion::OrdnerPfadAufloesen { .. } => "ordner_pfad_aufloesen",
        }
    }
}
