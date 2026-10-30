//! Portierte CE-Zeilen-Tests (Verhaltens-Referenz).

use super::*;

    #[test]
    fn roundtrip_lf_crlf_cr_ohne() {
        let text = "a\nb\r\nc\rd"; // LF, CRLF, CR, ohne Ende
        let z = zerlege(text);
        assert_eq!(z.len(), 4);
        assert_eq!(z[0].ende, Ende::Lf);
        assert_eq!(z[1].ende, Ende::Crlf);
        assert_eq!(z[2].ende, Ende::Cr);
        assert_eq!(z[3].ende, Ende::Ohne);
        assert_eq!(haenge_zusammen(&z), text);
    }

    #[test]
    fn leere_datei_und_nur_enden() {
        assert_eq!(zerlege("").len(), 0);
        let z = zerlege("\n\n\n");
        assert_eq!(z.len(), 3);
        assert!(z.iter().all(|x| x.inhalt.is_empty() && x.ende == Ende::Lf));
        assert_eq!(haenge_zusammen(&z), "\n\n\n");
        // \r\n\r\n\r\n-Kette (Test 18)
        let z = zerlege("\r\n\r\n\r\n");
        assert_eq!(z.len(), 3);
        assert_eq!(haenge_zusammen(&z), "\r\n\r\n\r\n");
        // Zeile nur aus Zeilenende an beliebigen Positionen (Test 17)
        let z = zerlege("x\n\n\ny");
        assert_eq!(z.len(), 4);
        assert_eq!(haenge_zusammen(&z), "x\n\n\ny");
    }

    #[test]
    fn u2028_2029_keine_umbrueche() {
        let text = "a\u{2028}b\u{2029}c";
        let z = zerlege(text);
        assert_eq!(z.len(), 1, "U+2028/29 dürfen Zeilen NIE trennen");
        assert_eq!(haenge_zusammen(&z), text);
    }

    #[test]
    fn keine_normalisierung() {
        // é fertig (NFC, 2 Bytes) vs. E + Akzent (NFD, 3 Bytes)
        let nfc = "caf\u{e9}";
        let nfd = "cafe\u{301}";
        assert_ne!(nfc.as_bytes(), nfd.as_bytes());
        assert_eq!(haenge_zusammen(&zerlege(nfc)), nfc);
        assert_eq!(haenge_zusammen(&zerlege(nfd)), nfd);
    }

    #[test]
    fn segment_grenzkorridor() {
        // exakt Limit, Limit+1, Limit-1 (Test 22)
        for n in [ZEILEN_LIMIT - 1, ZEILEN_LIMIT, ZEILEN_LIMIT + 1] {
            let z: String = "x".repeat(n);
            let segs = zerlege_segmente(&z);
            let zusammen = haenge_segmente_zusammen(&segs);
            assert_eq!(zusammen, z, "n={n} byte-identisch");
            assert_eq!(
                segs.len(),
                n.div_ceil(ZEILEN_LIMIT),
                "Segmentzahl bei n={n}"
            );
        }
    }

    #[test]
    fn segment_multibyte_nie_zerschnitten() {
        // 2-Byte-Zeichen über die Chunk-Grenze gelegt: Schnitt muss auf
        // Zeichengrenze zurückweichen (Off-by-one-Falle, Test 24).
        let z: String = "ä".repeat(ZEILEN_LIMIT / 2 + 5);
        let segs = zerlege_segmente(&z);
        assert!(segs.len() >= 2);
        for s in &segs {
            assert!(s.inhalt.len() <= ZEILEN_LIMIT);
            assert!(!s.inhalt.is_empty());
        }
        assert_eq!(haenge_segmente_zusammen(&segs), z);
    }

    #[test]
    fn emoji_rtl_kombinierende_ueberleben() {
        let text = "🇩🇪👨‍👩‍👧‍👦 \u{200d}\u{200c}\u{200b} شكرا תודה é\u{301}";
        assert_eq!(haenge_zusammen(&zerlege(text)), text);
    }

    #[test]
    fn tab_leerzeilen_orgie() {
        // 200 Leerzeilen mit gemischtem Whitespace (Test 16)
        let mut text = String::new();
        for i in 0..200 {
            text.push_str(if i % 3 == 0 { " \t" } else if i % 3 == 1 { "\t" } else { "  " });
            text.push('\n');
        }
        let z = zerlege(&text);
        assert_eq!(z.len(), 200);
        assert_eq!(haenge_zusammen(&z), text);
    }

    #[test]
    fn ende_code_roundtrip() {
        for e in [Ende::Ohne, Ende::Lf, Ende::Crlf, Ende::Cr] {
            assert_eq!(Ende::von_code(e.code()), e);
        }
        assert_eq!(Ende::von_code(99), Ende::Ohne);
    }
