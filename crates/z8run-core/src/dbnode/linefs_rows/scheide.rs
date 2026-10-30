//! M5.0/S5 — Text/Binär-Scheide (Bauplan §3.3/§3.3.1): deterministisch,
//! KEINE Heuristik. Die Dateiendung entscheidet NICHTS (nur Etikett).
//!
//! Vollständiger Byte-Scan JEDES Byte (beim Anlegen UND bei jedem Commit):
//!   · Check 1: ein einziges 0x00 irgendwo → BINÄR (in validem UTF-8
//!     mathematisch unmöglich; UTF-16 enthält Null-Bytes → BINÄR).
//!   · Check 2: strenge UTF-8-Validierung komplett (korrekte Multibyte-
//!     sequenzen, keine Overlongs, keine verwaisten Surrogate) — Rust
//!     `str::from_utf8` prüft exakt nach Spezifikation.
//!   · Gültiges UTF-8 + kein Null-Byte → TEXT (Zeilen-Welt).
//!   · Ungültiges UTF-8 + kein Null-Byte → DECKEL: Commit abgelehnt mit
//!     klarer Meldung (kein stiller Binärpfad, keine stille Konvertierung).
//!   · Overlong-Kodierungen und Einzel-Surrogate sind ungültiges UTF-8
//!     → DECKEL (Angriffsvektor geblockt).
//!
//! VERBOTEN und nicht enthalten: chardet & Co., libmagic/file als
//! ENTSCHEIDER. Kein Mischwesen: Text ODER Binär, Wechsel nur bewusst.

/// Prüfergebnis der Scheide.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Urteil {
    /// Sauberer Text (kein Null-Byte, gültiges UTF-8) → Zeilen-Welt.
    Text,
    /// Null-Byte gefunden → Binärpfad (S3 + eigener Key).
    Binaer,
    /// Ungültiges UTF-8 ohne Null-Byte → Commit-DECKEL mit Meldung.
    Deckel(&'static str),
}

/// Vollständiger Byte-Scan. JEDES Byte wird geprüft, kein Snippet-Snüffeln.
pub fn pruefe(bytes: &[u8]) -> Urteil {
    // Check 1: Null-Byte irgendwo (die Falle sitzt gern am Dateiende).
    if bytes.contains(&0u8) {
        return Urteil::Binaer;
    }
    // Check 2: strenge, komplette UTF-8-Validierung nach Spezifikation.
    match std::str::from_utf8(bytes) {
        Ok(_) => Urteil::Text,
        Err(_) => Urteil::Deckel(
            "DECKEL: ungültiges UTF-8 (kein Null-Byte, vermutlich altes Encoding wie Latin-1 \
             oder kaputte Sequenz) — zu UTF-8 konvertieren bzw. reparieren, DANN commiten. \
             Kein stiller Binärpfad, keine stille Umwandlung.",
        ),
    }
}

/// Wie `pruefe`, aber als Result mit harter Fehlermeldung für Commit-Pfade.
pub fn pruefe_fuer_commit(bytes: &[u8]) -> Result<(), String> {
    match pruefe(bytes) {
        Urteil::Text => Ok(()),
        Urteil::Binaer => Ok(()), // Aufrufer entscheidet über Binärpfad
        Urteil::Deckel(m) => Err(m.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sauberer_text_ist_text() {
        assert_eq!(pruefe(b"hallo\nwelt"), Urteil::Text);
        assert_eq!(pruefe(&[]), Urteil::Text);
        assert_eq!(pruefe("äöü ß 🇩🇪 שלום 中文\n".as_bytes()), Urteil::Text);
    }

    #[test]
    fn null_byte_ist_binaer() {
        assert_eq!(pruefe(b"a\x00b"), Urteil::Binaer);
        // Null-Byte am ENDE (späte Entdeckung, Test 38).
        assert_eq!(pruefe(b"sauberer text\n\x00"), Urteil::Binaer);
        // UTF-16LE "ab" = 61 00 62 00 → BINÄR (Test 2: UTF-16 via Null-Byte).
        assert_eq!(pruefe(&[0x61, 0x00, 0x62, 0x00]), Urteil::Binaer);
        // UTF-16-BOM LE (FF FE) + "a" → enthält Null-Bytes → BINÄR.
        assert_eq!(pruefe(&[0xff, 0xfe, 0x61, 0x00]), Urteil::Binaer);
    }

    #[test]
    fn latin1_ist_deckel() {
        // "ä" in Latin-1 = 0xE4 — ungültiges UTF-8 ohne Null-Byte.
        assert!(matches!(pruefe(&[0x61, 0xe4, 0x62]), Urteil::Deckel(_)));
        // DECKEL-Nachricht nennt den Weg (konvertieren, dann commiten).
        if let Urteil::Deckel(m) = pruefe(&[0xe4]) {
            assert!(m.contains("UTF-8") && m.contains("konvertieren"), "{m}");
        } else {
            panic!("Deckel erwartet");
        }
    }

    #[test]
    fn overlong_encoding_ist_deckel() {
        // U+002F als 2-Byte-Overlong: 0xC0 0xAF (Angriffsvektor, Test 3).
        assert!(matches!(pruefe(&[0xc0, 0xaf]), Urteil::Deckel(_)));
        // U+0000 overlong enthält kein Null-Byte, aber ungültig → Deckel.
        assert!(matches!(pruefe(&[0xc0, 0x80]), Urteil::Deckel(_)));
    }

    #[test]
    fn verwaistes_surrogat_ist_deckel() {
        // U+D800 als UTF-8-Kodierung (ED A0 80) — Surrogate verboten (Test 4).
        assert!(matches!(pruefe(&[0xed, 0xa0, 0x80]), Urteil::Deckel(_)));
        // RICHTIGES Paar in UTF-8 existiert nicht — nur in UTF-16;
        // 4-Byte-Emoji (Surrogatpaar in UTF-16) ist in UTF-8 F4-basiert gültig:
        assert_eq!(pruefe("😀".as_bytes()), Urteil::Text);
    }

    #[test]
    fn ungueltig_mitten_in_datei_deckel() {
        // Test 10: kaputte Sequenz mitten im sauberen Text.
        let mut b = b"guter text ".to_vec();
        b.push(0xff); // isoliertes continuation-byte
        b.extend_from_slice(b" weiter");
        assert!(matches!(pruefe(&b), Urteil::Deckel(_)));
    }

    #[test]
    fn bom_varianten() {
        // UTF-8-BOM am Anfang: gültiges UTF-8, kein Null-Byte → TEXT
        // (BOM bleibt Inhalt — kein heimliches Entfernen).
        let mit_bom = "\u{feff}inhalt\n".to_string();
        assert_eq!(pruefe(mit_bom.as_bytes()), Urteil::Text);
        // BOM mitten in der Datei: illegal-ish, aber gültiges UTF-8 → TEXT
        // (U+FEFF ist ein gültiges Zeichen; Zeilen-Welt hält es einfach aus).
        let mittel = "a\u{feff}b".to_string();
        assert_eq!(pruefe(mittel.as_bytes()), Urteil::Text);
    }

    #[test]
    fn commit_pfad_nimmt_deckel_ernst() {
        assert!(pruefe_fuer_commit(b"ok").is_ok());
        assert!(pruefe_fuer_commit(b"\x00\x01").is_ok()); // Binär ist KEIN Fehler
        assert!(pruefe_fuer_commit(&[0xe4]).is_err()); // Deckel blockt hart
    }
}
