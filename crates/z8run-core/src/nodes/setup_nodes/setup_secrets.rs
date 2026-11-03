//! "secrets"-Eintrag in der User-Hashdatei (Plugin-App-Prinzip, §23).
//!
//! Das Hashdatei-FORMAT (`Argon2IDHashDatei/3`) bleibt unverändert; neu sind
//! nur zwei Adressen/Blöcke je User:
//!   `secrets-ro-<addr>` (User-Passwort, read-only S3-Creds für den Proxy)
//!   `secrets-rw-<addr>` (Setup-Master, Write-Allow auf genau dieses Plugin)
//!
//! Altwelt-Hashdateien ohne diese Adressen bleiben gültig (Eintrag optional).
//! Versiegelung/Öffnung laufen ausschließlich über die bestehenden
//! Primitive aus `setup_crypto` — kein zweiter Wahrheitsort.

use serde_json::{json, Value};

use super::setup_crypto as sc;

pub const SECRETS_FORMAT: &str = "z8-secrets/1";
pub const SECRETS_RO_SALT: &str = "kv3-secrets-ro";
pub const SECRETS_RW_SALT: &str = "kv3-secrets-rw";

pub fn ro_addr(addr: &str) -> String {
    format!("secrets-ro-{addr}")
}

pub fn rw_addr(addr: &str) -> String {
    format!("secrets-rw-{addr}")
}

/// Ein geöffnetes "secrets"-Profil. `ro` = nur lesen (Proxy), `rw` = Setup.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretsProfil {
    pub cluster_id: String,
    pub bucket: String,
    pub prefix: String,
    pub region: String,
    pub providers: Vec<Value>,
    pub db_key_hex: String,
    pub read_only: bool,
}

impl SecretsProfil {
    pub fn als_json(&self) -> Value {
        json!({
            "format": SECRETS_FORMAT,
            "cluster_id": self.cluster_id,
            "bucket": self.bucket,
            "prefix": self.prefix,
            "region": self.region,
            "providers": self.providers,
            "db_key_hex": self.db_key_hex,
            "read_only": self.read_only,
            "write_allow": !self.read_only,
        })
    }

    pub fn aus_json(v: &Value) -> Result<Self, String> {
        if v["format"].as_str() != Some(SECRETS_FORMAT) {
            return Err("secrets: unbekanntes Format".into());
        }
        let providers = v["providers"].as_array().cloned().unwrap_or_default();
        Ok(Self {
            cluster_id: v["cluster_id"].as_str().ok_or("secrets: cluster_id fehlt")?.to_string(),
            bucket: v["bucket"].as_str().ok_or("secrets: bucket fehlt")?.to_string(),
            prefix: v["prefix"].as_str().unwrap_or_default().to_string(),
            region: v["region"].as_str().unwrap_or_default().to_string(),
            providers,
            db_key_hex: v["db_key_hex"].as_str().ok_or("secrets: db_key_hex fehlt")?.to_string(),
            read_only: v["read_only"].as_bool().unwrap_or(true),
        })
    }
}

/// Versiegelt ein Profil mit den bestehenden passbox-Primitiven.
pub fn profil_siegeln(
    profil: &SecretsProfil,
    passwort: &str,
    salt: &str,
    aad: &str,
) -> Result<Value, String> {
    sc::passbox(passwort, salt, &profil.als_json(), aad)
}

fn block_name(addr: &str) -> String {
    format!("Block-{addr}")
}

/// Baut die Hashdatei neu und ersetzt/ergänzt die beiden secrets-Blöcke.
/// Alle vorhandenen Blöcke (User-Block, Setup-Plugins, HW) bleiben erhalten.
pub fn eintrag_hinzufuegen(
    text: &str,
    addr: &str,
    ro_box: &Value,
    rw_box: &Value,
) -> Result<String, String> {
    let (addrs, blocks) = sc::hashdatei_parsen(text);
    let roa = ro_addr(addr);
    let rwa = rw_addr(addr);
    let rob = block_name(&roa);
    let rwb = block_name(&rwa);
    let mut new_addrs: Vec<(String, String)> = Vec::new();
    let mut new_blocks: Vec<(String, String)> = Vec::new();
    for (a, b) in &addrs {
        if a == &roa || a == &rwa {
            continue;
        }
        new_addrs.push((a.clone(), b.clone()));
    }
    for (b, c) in &blocks {
        if b == &rob || b == &rwb {
            continue;
        }
        new_blocks.push((b.clone(), c.clone()));
    }
    new_addrs.push((roa, rob.clone()));
    new_addrs.push((rwa, rwb.clone()));
    new_blocks.push((rob, sc::box_b64(ro_box)?));
    new_blocks.push((rwb, sc::box_b64(rw_box)?));
    Ok(sc::hashdatei_bauen(&new_addrs, &new_blocks))
}

/// Hashdatei ohne secrets-Eintrag (für Tests/Negativfälle).
pub fn eintrag_entfernen(text: &str, addr: &str) -> String {
    let (addrs, blocks) = sc::hashdatei_parsen(text);
    let roa = ro_addr(addr);
    let rwa = rw_addr(addr);
    let rob = block_name(&roa);
    let rwb = block_name(&rwa);
    let a: Vec<(String, String)> = addrs.into_iter().filter(|(x, _)| x != &roa && x != &rwa).collect();
    let b: Vec<(String, String)> = blocks.into_iter().filter(|(x, _)| x != &rob && x != &rwb).collect();
    sc::hashdatei_bauen(&a, &b)
}

fn chiffre_fuer(text: &str, addr: &str) -> Option<String> {
    let (addrs, blocks) = sc::hashdatei_parsen(text);
    let block = addrs.iter().find(|(a, _)| a == addr).map(|(_, b)| b.clone())?;
    blocks.into_iter().find(|(b, _)| b == &block).map(|(_, c)| c)
}

pub fn hat_eintrag(text: &str, addr: &str) -> bool {
    chiffre_fuer(text, &ro_addr(addr)).is_some() && chiffre_fuer(text, &rw_addr(addr)).is_some()
}

pub fn eintrag_oeffnen_ro(
    text: &str,
    addr: &str,
    passwort: &str,
    user_salt: &str,
) -> Result<Option<SecretsProfil>, String> {
    let Some(chiffre) = chiffre_fuer(text, &ro_addr(addr)) else {
        return Ok(None);
    };
    let box_val = sc::box_aus_b64(&chiffre)?;
    let plain = sc::passbox_oeffne(&box_val, passwort, user_salt)?;
    Ok(Some(SecretsProfil::aus_json(&plain)?))
}

pub fn eintrag_oeffnen_rw(
    text: &str,
    addr: &str,
    master_hex: &str,
) -> Result<Option<SecretsProfil>, String> {
    let Some(chiffre) = chiffre_fuer(text, &rw_addr(addr)) else {
        return Ok(None);
    };
    let box_val = sc::box_aus_b64(&chiffre)?;
    let plain = sc::passbox_oeffne(&box_val, master_hex, SECRETS_RW_SALT)?;
    Ok(Some(SecretsProfil::aus_json(&plain)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profil(read_only: bool) -> SecretsProfil {
        SecretsProfil {
            cluster_id: "cl-1".into(),
            bucket: "secret-bucket".into(),
            prefix: "secret-cluster/cl-1/".into(),
            region: "de-fra-1".into(),
            providers: vec![json!({"name": "p1", "endpoint": "https://s3.example",
                "region": "de-fra-1", "bucket": "secret-bucket",
                "access_key": "AK", "secret_key": "SK"})],
            db_key_hex: "ab".repeat(32),
            read_only,
        }
    }

    fn user_hashdatei(addr: &str) -> String {
        // Altwelt-Hashdatei (nur User-Block) — exakt das bestehende Format.
        let user_text = sc::hashdatei_bauen(
            &[(addr.to_string(), "Block-1".into())],
            &[("Block-1".into(), sc::box_b64(&json!({"plugins": []})).unwrap())],
        );
        user_text
    }

    #[test]
    fn baut_und_liest_beide_profile() {
        let addr = "addr-anna";
        let text = user_hashdatei(addr);
        let ro = profil(true);
        let rw = profil(false);
        let ro_box = profil_siegeln(&ro, "pw", SECRETS_RO_SALT, "kv3-secrets-ro").unwrap();
        let rw_box = profil_siegeln(&rw, "master", SECRETS_RW_SALT, "kv3-secrets-rw").unwrap();
        let neu = eintrag_hinzufuegen(&text, addr, &ro_box, &rw_box).unwrap();
        assert!(hat_eintrag(&neu, addr));
        let gelesen_ro = eintrag_oeffnen_ro(&neu, addr, "pw", SECRETS_RO_SALT).unwrap().unwrap();
        assert_eq!(gelesen_ro, ro);
        assert!(gelesen_ro.read_only);
        let gelesen_rw = eintrag_oeffnen_rw(&neu, addr, "master").unwrap().unwrap();
        assert_eq!(gelesen_rw, rw);
        assert!(!gelesen_rw.read_only);
    }

    #[test]
    fn ersetzt_statt_dupliziert() {
        let addr = "addr-anna";
        let text = user_hashdatei(addr);
        let box1 = profil_siegeln(&profil(true), "pw", SECRETS_RO_SALT, "kv3-secrets-ro").unwrap();
        let box2 = profil_siegeln(&profil(false), "m1", SECRETS_RW_SALT, "kv3-secrets-rw").unwrap();
        let t1 = eintrag_hinzufuegen(&text, addr, &box1, &box2).unwrap();
        let box3 = profil_siegeln(&profil(false), "m2", SECRETS_RW_SALT, "kv3-secrets-rw").unwrap();
        let t2 = eintrag_hinzufuegen(&t1, addr, &box1, &box3).unwrap();
        let (addrs, _) = sc::hashdatei_parsen(&t2);
        assert_eq!(addrs.iter().filter(|(a, _)| a == &ro_addr(addr)).count(), 1);
        assert_eq!(addrs.iter().filter(|(a, _)| a == &rw_addr(addr)).count(), 1);
        assert_eq!(eintrag_oeffnen_rw(&t2, addr, "m2").unwrap().unwrap().db_key_hex, "ab".repeat(32));
    }

    #[test]
    fn altwelt_ohne_eintrag_bleibt_gueltig() {
        let addr = "addr-alt";
        let text = user_hashdatei(addr);
        assert!(!hat_eintrag(&text, addr));
        assert!(eintrag_oeffnen_ro(&text, addr, "pw", SECRETS_RO_SALT).unwrap().is_none());
        assert!(eintrag_oeffnen_rw(&text, addr, "master").unwrap().is_none());
        let (addrs, blocks) = sc::hashdatei_parsen(&text);
        assert_eq!(addrs, vec![(addr.to_string(), "Block-1".to_string())]);
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn falsches_passwort_scheitert() {
        let addr = "addr-anna";
        let text = user_hashdatei(addr);
        let ro_box = profil_siegeln(&profil(true), "pw", SECRETS_RO_SALT, "kv3-secrets-ro").unwrap();
        let rw_box = profil_siegeln(&profil(false), "master", SECRETS_RW_SALT, "kv3-secrets-rw").unwrap();
        let neu = eintrag_hinzufuegen(&text, addr, &ro_box, &rw_box).unwrap();
        assert!(eintrag_oeffnen_ro(&neu, addr, "falsch", SECRETS_RO_SALT).is_err());
        assert!(eintrag_oeffnen_rw(&neu, addr, "falsch").is_err());
    }
}
