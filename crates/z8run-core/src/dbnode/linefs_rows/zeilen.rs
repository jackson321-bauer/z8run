//! M5.0/S3 — Das Zeilen-Modell (Bauplan §3.2): reine Logik, keine DB.
//!
//!   · Zeilen trennen NUR an echten Zeilenenden: LF, CRLF, CR (klassischer
//!     Mac). U+2028/U+2029 sind KEINE Zeilenumbrüche — sie bleiben Inhalt
//!     (Folter-Test 1).
//!   · JEDE Zeile trägt ihr eigenes Ende (0=ohne,1=LF,2=CRLF,3=CR) —
//!     CRLF/LF/CR-Mischformen überleben byte-identisch (Tests 11-18).
//!   · KEINE Normalisierung: NFC/NFD, é als E+Akzent usw. bleiben
//!     byte-genau erhalten (Tests 7/8).
//!   · Segment-Wachstum (Zeilenmonster): logische Zeile > ZEILEN_LIMIT
//!     Bytes wird physisch in Segmente zerlegt (fester Byte-Chunk, Schnitt
//!     NUR an UTF-8-Zeichengrenzen — nie mitten im Multibyte). Der
//!     Dispatcher hängt Segmente beim Lesen zu EINER Zeile zusammen.

use super::schema::ZEILEN_LIMIT;

/// Zeilenende-Varianten (pro Zeile gespeichert).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ende {
    Ohne,
    Lf,
    Crlf,
    Cr,
}

impl Ende {
    pub fn code(self) -> i64 {
        match self {
            Ende::Ohne => 0,
            Ende::Lf => 1,
            Ende::Crlf => 2,
            Ende::Cr => 3,
        }
    }
    pub fn von_code(c: i64) -> Ende {
        match c {
            1 => Ende::Lf,
            2 => Ende::Crlf,
            3 => Ende::Cr,
            _ => Ende::Ohne,
        }
    }
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Ende::Ohne => b"",
            Ende::Lf => b"\n",
            Ende::Crlf => b"\r\n",
            Ende::Cr => b"\r",
        }
    }
}

/// EINE logische Zeile (unzerlegt): Inhalt + eigenes Ende.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Zeile {
    pub inhalt: String,
    pub ende: Ende,
}

/// Zerlegt Rohtext in logische Zeilen mit ihren echten Enden.
/// Nur LF/CRLF/CR trennen; alles andere (inkl. U+2028/29) bleibt Inhalt.
pub fn zerlege(text: &str) -> Vec<Zeile> {
    let bytes = text.as_bytes();
    let mut zeilen = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                zeilen.push(Zeile {
                    inhalt: text[start..i].to_string(),
                    ende: Ende::Lf,
                });
                i += 1;
                start = i;
            }
            b'\r' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    zeilen.push(Zeile {
                        inhalt: text[start..i].to_string(),
                        ende: Ende::Crlf,
                    });
                    i += 2;
                } else {
                    zeilen.push(Zeile {
                        inhalt: text[start..i].to_string(),
                        ende: Ende::Cr,
                    });
                    i += 1;
                }
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        zeilen.push(Zeile {
            inhalt: text[start..].to_string(),
            ende: Ende::Ohne,
        });
    }
    zeilen
}

/// Hängt Zeilen wieder zum Rohtext zusammen (byte-identisch zum Input).
pub fn haenge_zusammen(zeilen: &[Zeile]) -> String {
    let mut out = String::with_capacity(zeilen.iter().map(|z| z.inhalt.len() + 2).sum());
    for z in zeilen {
        out.push_str(&z.inhalt);
        out.push_str(std::str::from_utf8(z.ende.bytes()).unwrap());
    }
    out
}

/// EIN physisches Segment EINER logischen Zeile.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Segment {
    pub inhalt: String,
}

/// Zerlegt EINE logische Zeile in Segmente (fester Byte-Chunk, nur an
/// UTF-8-Zeichengrenzen). Zeile ≤ ZEILEN_LIMIT → genau 1 Segment.
pub fn zerlege_segmente(zeile: &str) -> Vec<Segment> {
    let bytes = zeile.as_bytes();
    if bytes.len() <= ZEILEN_LIMIT {
        return vec![Segment {
            inhalt: zeile.to_string(),
        }];
    }
    let mut segs = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        let mut ende = (start + ZEILEN_LIMIT).min(bytes.len());
        // Zurücklaufen zur UTF-8-Zeichengrenze (Anfang eines Multibyte).
        while ende < bytes.len() && (bytes[ende] & 0xC0) == 0x80 {
            ende -= 1;
        }
        // Sicherheitsnetz:Chunk < Limit-3 kann nie nur Fortsetzungsbytes
        // sein, weil Limit die Max-Zeichenlänge (4) übersteigt.
        debug_assert!(ende > start, "Schnitt muss auf Zeichengrenze bleiben");
        segs.push(Segment {
            inhalt: String::from_utf8(bytes[start..ende].to_vec())
                .expect("Schnitt auf Zeichengrenze"),
        });
        start = ende;
    }
    segs
}

/// Hängt Segmente zu EINER logischen Zeile zusammen (Dispatcher-Sicht).
pub fn haenge_segmente_zusammen(segs: &[Segment]) -> String {
    let mut out = String::with_capacity(segs.iter().map(|s| s.inhalt.len()).sum());
    for s in segs {
        out.push_str(&s.inhalt);
    }
    out
}

#[cfg(test)]
#[path = "zeilen_tests.rs"]
mod tests;
