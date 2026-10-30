//! Reine Sicht-Funktionen der Zeilen-Welt (Port des CE-Kerns):
//! IST -> Sitzung, Zeitmaschine, Zeilen-Historie, Hashketten-Verifikation.

use super::typen::{zeilen_hash, EpocheRoh, IstZeile, KettenZeile, ZeileStand};
use super::zeilen::{Ende, Zeile};

/// IST-Segment-Zeilen -> Sitzungs-Zeilen (Segmente joinen, nach nr).
pub fn ist_zu_stand(ist: &[IstZeile]) -> Vec<ZeileStand> {
    let mut map: std::collections::BTreeMap<(i64, i64), ZeileStand> =
        std::collections::BTreeMap::new();
    for z in ist {
        let e = map.entry((z.nr, z.schluessel)).or_insert(ZeileStand {
            schluessel: Some(z.schluessel),
            inhalt: String::new(),
            ende: Ende::von_code(z.ende),
            geloescht: z.geloescht,
        });
        e.inhalt.push_str(&z.inhalt);
    }
    map.into_values().collect()
}

/// Sitzungs-Zeilen -> reine Zeilen (fuers Rendern, ohne Grabmaele).
pub fn als_zeilen(stand: &[ZeileStand]) -> Vec<Zeile> {
    stand
        .iter()
        .filter(|z| !z.geloescht)
        .map(|z| Zeile { inhalt: z.inhalt.clone(), ende: z.ende })
        .collect()
}

/// Zeitmaschine: je Schluessel die neueste Fassung <= X.
pub fn fassung_aus_epochen(epochen: &[EpocheRoh]) -> Vec<ZeileStand> {
    let mut versionen: std::collections::BTreeMap<(i64, i64), (i64, String, Ende, bool)> =
        std::collections::BTreeMap::new();
    for z in epochen {
        let e = versionen
            .entry((z.schluessel, z.fassung))
            .or_insert((z.nr, String::new(), Ende::von_code(z.ende), z.geloescht));
        e.1.push_str(&z.inhalt);
    }
    let mut neueste: std::collections::BTreeMap<i64, (i64, i64)> = std::collections::BTreeMap::new();
    for (schl, fass) in versionen.keys() {
        let e = neueste.entry(*schl).or_insert((*schl, *fass));
        if *fass > e.1 {
            e.1 = *fass;
        }
    }
    let mut zeilen: Vec<(i64, ZeileStand)> = Vec::new();
    for (schl, (_, fass)) in &neueste {
        if let Some((nr, inhalt, ende, gel)) = versionen.get(&(*schl, *fass)) {
            if !gel {
                zeilen.push((
                    *nr,
                    ZeileStand {
                        schluessel: Some(*schl),
                        inhalt: inhalt.clone(),
                        ende: *ende,
                        geloescht: false,
                    },
                ));
            }
        }
    }
    zeilen.sort_by_key(|(nr, _)| *nr);
    zeilen.into_iter().map(|(_, z)| z).collect()
}

/// Zeilen-Historie: (Fassung, Inhalt, Ende) je Version eines Schluessels.
pub fn historie_aus_epochen(epochen: &[EpocheRoh]) -> Result<Vec<(i64, String, Ende)>, String> {
    let mut map: std::collections::BTreeMap<i64, (String, Ende, bool)> =
        std::collections::BTreeMap::new();
    for z in epochen {
        let e = map
            .entry(z.fassung)
            .or_insert((String::new(), Ende::von_code(z.ende), z.geloescht));
        e.0.push_str(&z.inhalt);
    }
    Ok(map.into_iter().map(|(f, (i, e, _))| (f, i, e)).collect())
}

/// Ketten-Verifikation (datei_id ist Bestandteil jedes Zeilen-Hashes).
pub fn kette_pruefen_daten(datei_id: i64, zeilen: &[KettenZeile], kopf_hash: &str) -> bool {
    let mut vor = String::new();
    for z in zeilen {
        if z.vor_hash != vor {
            return false;
        }
        let soll = zeilen_hash(
            &z.vor_hash,
            datei_id,
            z.seite,
            z.schluessel,
            z.nr,
            z.seg,
            &z.inhalt,
            Ende::von_code(z.ende),
            z.geloescht,
            z.fassung,
            &z.ts,
            &z.urheber,
        );
        if soll != z.hash {
            return false;
        }
        vor = z.hash.clone();
    }
    kopf_hash == vor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fassung_und_historie_aus_epochen() {
        let e = vec![
            EpocheRoh { schluessel: 1, fassung: 1, nr: 1, inhalt: "a".into(), ende: 1, geloescht: false },
            EpocheRoh { schluessel: 1, fassung: 2, nr: 1, inhalt: "b".into(), ende: 1, geloescht: false },
            EpocheRoh { schluessel: 2, fassung: 1, nr: 2, inhalt: "c".into(), ende: 1, geloescht: false },
        ];
        let v2 = fassung_aus_epochen(&e);
        assert_eq!(v2.len(), 2);
        assert_eq!(v2[0].inhalt, "b");
        let h = historie_aus_epochen(&e[..2]).unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].1, "a");
    }
}
