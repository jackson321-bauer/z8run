//! Einmal-Challenges für WebAuthn: serverseitig gespeichert, mit Ablauf.
//! Dateiname = sha256(user); Inhalt {user, challenge, expires}.

use serde_json::{json, Value};
use sha2::Digest;

use super::setup_crypto as sc;

fn pfad(dir: &str, user: &str) -> std::path::PathBuf {
    let h = sc::sha_hex(format!("challenge:{user}").as_bytes());
    std::path::Path::new(dir).join(format!("{h}.json"))
}

pub fn speichere(dir: &str, user: &str, challenge: &str, ttl_secs: u64) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("challenge dir {dir}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let ablauf = chrono::Utc::now().timestamp() + ttl_secs as i64;
    let inhalt = json!({"user": user, "challenge": challenge, "expires": ablauf});
    let path = pfad(dir, user);
    std::fs::write(&path, inhalt.to_string()).map_err(|e| format!("challenge write: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Prüft Challenge + Ablauf und verbraucht sie (einmalig).
pub fn verbrauche(dir: &str, user: &str, challenge: &str) -> Result<(), String> {
    let path = pfad(dir, user);
    let raw = std::fs::read_to_string(&path).map_err(|_| "Challenge nicht gefunden (neu anfordern)")?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("Challenge-JSON: {e}"))?;
    if v["challenge"].as_str() != Some(challenge) {
        return Err("Challenge stimmt nicht mit der ausgegebenen überein".into());
    }
    if v["expires"].as_i64().unwrap_or(0) < chrono::Utc::now().timestamp() {
        let _ = std::fs::remove_file(&path);
        return Err("Challenge abgelaufen".into());
    }
    std::fs::remove_file(&path).map_err(|e| format!("Challenge verbrauchen: {e}"))?;
    let _ = sha2::Sha256::digest(user.as_bytes());
    Ok(())
}
