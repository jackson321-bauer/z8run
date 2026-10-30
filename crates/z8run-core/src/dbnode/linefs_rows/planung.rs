//! Commit-Planung der Zeilen-Welt (Port des CE-Kerns).
//!
//! Reine Planung: erzeugt SQL-Aktionen (WAL-faehig), fuehrt nichts aus.
//! Epochen, lueckenlose Nummerierung, Identitaet (schluessel), Grabmaele,
//! Hashkette und DECKEL (veralteter Stand / ungueltige Policy) sind 1:1
//! aus dem CE-Kern gespiegelt. Unterschied: die 205er-POLICY ist Konfig
//! (0 = aus), die physikalische Seitengroesse bleibt 205.

use super::schema::{ddl_seite, seite_von_nr, tabelle_seite, SEITE_MAX};
use super::typen::{zeilen_hash, Aktion, DateiKopf, IstZeile, ZeileStand};
use super::zeilen::{zerlege_segmente, Ende};
use serde_json::json;

/// Zeilen-Policy aus der dbnode-config.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// 0 = unbegrenzt; >0 = harte Grenze.
    pub limit: u32,
    /// Code/Doku-Unterscheidung an/aus (Default aus).
    pub code_docu: bool,
}

/// Effektive Grenze fuer eine Datei. Code/Doku AUS = keine Sonderbehandlung
/// (Grenze gilt fuer alle); AN = Dokumente sind unbegrenzt (Auto-Paging).
pub fn effektive_grenze(art: &str, policy: &Policy) -> u32 {
    if policy.limit == 0 {
        return 0;
    }
    if policy.code_docu && art != "code" {
        0
    } else {
        policy.limit
    }
}

/// Plant den Commit eines neuen Datei-Stands.
/// basis = Fassung, auf der die Session arbeitet (DECKEL veralteter Stand).
/// Rueckgabe leer = no-op (keine neue Fassung, kein Fake-WAL).
#[allow(clippy::too_many_arguments)]
pub fn plane_commit_daten(
    kopf: &DateiKopf,
    datei_id: i64,
    basis: i64,
    ist: &[IstZeile],
    ziel: &[ZeileStand],
    urheber: &str,
    ts: &str,
    policy: &Policy,
) -> Result<Vec<Aktion>, String> {
    let (name, art, fassung, hashkette) = (&kopf.name, &kopf.art, kopf.fassung, &kopf.hashkette);
    if basis != fassung {
        return Err(format!(
            "DECKEL veralteter Stand: Datei {name:?} hat Fassung {fassung}, Session basiert auf {basis} — neu öffnen"
        ));
    }
    let grenze = effektive_grenze(art, policy);
    let anzahl = ziel.iter().filter(|z| !z.geloescht).count() as u32;
    if grenze > 0 && anzahl > grenze {
        return Err(format!(
            "ZEILEN-LIMIT: Datei {name:?} hätte {anzahl} Zeilen — HART blockiert (max {grenze})"
        ));
    }
    let ist: Vec<IstZeile> = ist.to_vec();
    let mut max_key: i64 = ist.iter().map(|z| z.schluessel).max().unwrap_or(0);
    let neu_fassung = fassung + 1;
    let mut aktionen = Vec::new();
    let mut vor_hash = hashkette.clone();
    let mut geaendert = 0u64;
    let seitenzahl = ziel.len().div_ceil(SEITE_MAX as usize).max(1) as i64;
    for s in 1..=seitenzahl {
        aktionen.push(Aktion {
            sql: "INSERT OR IGNORE INTO seiten (datei_id, seite) VALUES (?1, ?2)".into(),
            params: vec![json!(datei_id), json!(s)],
        });
        aktionen.push(Aktion {
            sql: ddl_seite(datei_id as u64, s as u32),
            params: vec![],
        });
    }
    fn version(
        aktionen: &mut Vec<Aktion>,
        datei_id: i64,
        ist_segs: &[IstZeile],
        schluessel: i64,
        nr: i64,
        inhalt: &str,
        ende: Ende,
        geloescht: bool,
        neu_fassung: i64,
        ts: &str,
        urheber: &str,
        vor_hash: &mut String,
    ) {
        for alt in ist_segs {
            let t = tabelle_seite(datei_id as u64, seite_von_nr(alt.nr) as u32);
            aktionen.push(Aktion {
                sql: format!("DELETE FROM {t} WHERE schluessel = ?1"),
                params: vec![json!(schluessel)],
            });
        }
        let seite = seite_von_nr(nr);
        let t_neu = tabelle_seite(datei_id as u64, seite as u32);
        let ziel_segs: Vec<String> = if geloescht {
            vec![String::new()]
        } else {
            zerlege_segmente(inhalt)
                .iter()
                .map(|s| s.inhalt.clone())
                .collect()
        };
        for (si, seg_inhalt) in ziel_segs.iter().enumerate() {
            let seg = si as i64 + 1;
            aktionen.push(Aktion {
                sql: format!(
                    "INSERT INTO {t_neu} (schluessel, nr, seg, inhalt, ende, fassung, geloescht)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                ),
                params: vec![
                    json!(schluessel), json!(nr), json!(seg), json!(seg_inhalt),
                    json!(ende.code()), json!(neu_fassung), json!(geloescht as i64),
                ],
            });
            let h = zeilen_hash(
                vor_hash, datei_id, seite, schluessel, nr, seg, seg_inhalt, ende,
                geloescht, neu_fassung, ts, urheber,
            );
            aktionen.push(Aktion {
                sql: "INSERT INTO zeilen_epochen
                      (datei_id, seite, schluessel, nr, seg, inhalt, ende, fassung, geloescht, ts, urheber, vor_hash, hash)
                      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"
                    .into(),
                params: vec![
                    json!(datei_id), json!(seite), json!(schluessel), json!(nr), json!(seg),
                    json!(seg_inhalt), json!(ende.code()), json!(neu_fassung),
                    json!(geloescht as i64), json!(ts), json!(urheber), json!(vor_hash), json!(h),
                ],
            });
            *vor_hash = h;
        }
    }
    for (idx, z) in ziel.iter().enumerate() {
        let nr = idx as i64 + 1;
        let schluessel = match z.schluessel {
            Some(k) => k,
            None => {
                max_key += 1;
                max_key
            }
        };
        let ist_segs: Vec<IstZeile> =
            ist.iter().filter(|i| i.schluessel == schluessel).cloned().collect();
        let ist_tombstone = ist_segs.len() == 1 && ist_segs[0].geloescht;
        let ziel_segs: Vec<String> = if z.geloescht {
            vec![String::new()]
        } else {
            zerlege_segmente(&z.inhalt).iter().map(|s| s.inhalt.clone()).collect()
        };
        let unveraendert = !ist_segs.is_empty()
            && ist_tombstone == z.geloescht
            && ist_segs[0].nr == nr
            && Ende::von_code(ist_segs[0].ende) == z.ende
            && ist_segs.len() == ziel_segs.len()
            && ist_segs.iter().zip(ziel_segs.iter()).all(|(a, s)| a.inhalt == *s);
        if unveraendert {
            continue;
        }
        geaendert += 1;
        version(
            &mut aktionen, datei_id, &ist_segs, schluessel, nr,
            if z.geloescht { "" } else { &z.inhalt }, z.ende, z.geloescht,
            neu_fassung, ts, urheber, &mut vor_hash,
        );
    }
    let ziel_keys: std::collections::HashSet<i64> =
        ziel.iter().filter_map(|z| z.schluessel).collect();
    let mut fehlende: Vec<i64> = ist
        .iter()
        .map(|z| z.schluessel)
        .filter(|k| !ziel_keys.contains(k))
        .collect();
    fehlende.sort();
    fehlende.dedup();
    for k in fehlende {
        let alte: Vec<IstZeile> = ist.iter().filter(|i| i.schluessel == k).cloned().collect();
        if alte.iter().all(|a| a.geloescht) {
            continue;
        }
        let nr = alte.first().map(|a| a.nr).unwrap_or(1);
        let ende = alte.first().map(|a| Ende::von_code(a.ende)).unwrap_or(Ende::Lf);
        geaendert += 1;
        version(&mut aktionen, datei_id, &alte, k, nr, "", ende, true, neu_fassung, ts, urheber, &mut vor_hash);
    }
    if geaendert == 0 {
        return Ok(Vec::new());
    }
    aktionen.push(Aktion {
        sql: "UPDATE dateien SET fassung = ?1, hashkette = ?2, ts = ?3, urheber = ?4 WHERE datei_id = ?5".into(),
        params: vec![json!(neu_fassung), json!(vor_hash), json!(ts), json!(urheber), json!(datei_id)],
    });
    Ok(aktionen)
}
