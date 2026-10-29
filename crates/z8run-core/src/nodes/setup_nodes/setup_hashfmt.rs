//! Argon2IDHashDatei/3-Format (Bauen/Parsen) — aus setup_crypto ausgelagert.

use super::setup_crypto::HASH_DATEI_KOPF;

pub fn hashdatei_bauen(addrs: &[(String, String)], chiffren: &[(String, String)]) -> String {
    let sb: Vec<String> = addrs.iter().map(|(a, b)| format!("{a} = {b}")).collect();
    let en: Vec<String> = chiffren.iter().map(|(b, c)| format!("{b}\n{c}")).collect();
    format!(
        "{HASH_DATEI_KOPF}\nwirt_min = 1.4.0\nnr = 1\n\nSecretboxes\nAnfang\n{}\nEnde\n\nEncrypted\nAnfang\n{}\nEnde\n",
        sb.join("\n"),
        en.join("\n\n")
    )
}

pub type HashEintraege = Vec<(String, String)>;
pub type ParsedHashdatei = (HashEintraege, HashEintraege);

/// Parst eine Hashdatei in (Adressen, Blöcke) — Format wie seed_welt2.
pub fn hashdatei_parsen(text: &str) -> ParsedHashdatei {
    let mut addrs = Vec::new();
    let mut blocks = Vec::new();
    let mut section = 0u8;
    let mut cur = String::new();
    let mut buf = String::new();
    for line in text.lines() {
        let t = line.trim();
        match t {
            "Secretboxes" => section = 1,
            "Encrypted" => section = 2,
            "Ende" => {
                if section == 2 && !cur.is_empty() {
                    blocks.push((cur.clone(), buf.trim().to_string()));
                    cur.clear();
                    buf.clear();
                }
            }
            "Anfang" => {}
            _ if section == 1 => {
                if let Some((a, b)) = t.split_once(" = ") {
                    addrs.push((a.to_string(), b.trim().to_string()));
                }
            }
            _ if section == 2 => {
                if t.starts_with("Block-") {
                    if !cur.is_empty() {
                        blocks.push((cur.clone(), buf.trim().to_string()));
                        buf.clear();
                    }
                    cur = t.to_string();
                } else if !t.is_empty() {
                    buf.push_str(line);
                    buf.push('\n');
                }
            }
            _ => {}
        }
    }
    (addrs, blocks)
}

