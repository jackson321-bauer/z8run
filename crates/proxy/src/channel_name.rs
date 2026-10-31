//! Kanal-Namen (G4): `{app}/{kanal}` oder `{app}/{kanal}/{session}`.

/// Erlaubt sind 2 oder 3 Segmente, je 1..=64 Zeichen aus [A-Za-z0-9-_.:].
pub fn valid_channel(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    (parts.len() == 2 || parts.len() == 3)
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c))
        })
}
