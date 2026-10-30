//! Portierter LineFS-Zeilen-Kern (CE-Verhalten) fuer den z8-DB-Node.
//!
//! Die Kern-Dateien (zeilen.rs, scheide.rs) sind verhaltensgleich aus dem
//! CE-Kern uebernommen (siehe S0-Log: MODULIMPORT, kein path-dep). Die
//! Schema-/Planungs-Dateien tragen ausschliesslich die drei im Bauplan
//! erlaubten Adaptionen (Policy als Konfig, art-Policy aus, kein
//! binaer_s3/Secret.db). Das CE-REPO bleibt unangetastet.

pub mod befehle;
pub mod planung;
pub mod schema;
pub mod scheide;
pub mod sicht;
pub mod typen;
pub mod zeilen;

pub use befehle::{LinefsAktion, LinefsRequest};
pub use planung::{effektive_grenze, plane_commit_daten, Policy};
pub use schema::{ddl_global, ddl_seite, seite_von_nr, tabelle_seite, ORDNER_WURZEL};
pub use sicht::{als_zeilen, fassung_aus_epochen, historie_aus_epochen, ist_zu_stand, kette_pruefen_daten};
pub use typen::{Aktion, DateiKopf, EpocheRoh, IstZeile, KettenZeile, ZeileStand};
pub use zeilen::{haenge_zusammen, zerlege, Ende};
