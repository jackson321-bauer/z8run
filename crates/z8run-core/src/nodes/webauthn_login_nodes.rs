//! WebAuthn-Login-Nodes (Faktor 2) — native Übernahme der Setup-Prüfung.
//!
//! Der Client öffnet seine HW-Shard-Box ausschließlich lokal (ECDH P-256 +
//! ML-KEM-1024); der Flow sieht nur den bereits geöffneten `shamir_hw`.
//! Publickey-Registry je User: `b2b/<addr_user>-webauthn.json` (nur Pubkeys).

use serde_json::{json, Value};

use super::setup_nodes::setup_challenge;
use super::setup_nodes::setup_io::{body, text};
use super::setup_nodes::setup_registry as reg;
use super::setup_nodes::setup_webauthn_assert::pruefe_assertion;
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

pub fn credential_registry_key(addr: &str) -> String {
    format!("b2b/{addr}-webauthn.json")
}

fn err(msg: &FlowMessage, e: impl Into<String>) -> Vec<FlowMessage> {
    vec![msg.derive(
        msg.source_node,
        "error",
        json!({"status": 401, "error": e.into()}),
    )]
}

/// Prüft Assertion gegen EINEN registrierten Credential-Eintrag.
/// Software-Passkeys brauchen einen PQC-Pubkey (für die Credential-Box);
/// echte Hardware-Keys ohne ECDH bleiben beim PEM-Weg (kein stiller Fallback).
pub fn pruefe_credential(
    cred: &Value,
    auth_b64: &str,
    cd_b64: &str,
    sig_b64: &str,
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> Result<u32, String> {
    let key_type = cred["key_type"].as_str().unwrap_or("webauthn-software");
    if key_type != "webauthn-software" {
        return Err(format!(
            "Credential key_type={key_type}: WebAuthn-Login nur für software-Passkeys (Hardware/PEM-Weg nutzen)"
        ));
    }
    if cred["pqc_pub_b64"].as_str().unwrap_or_default().is_empty() {
        return Err(
            "Credential ohne PQC-Pubkey (kein ECDH/KEM): Login nur über den PEM-Weg".into(),
        );
    }
    pruefe_assertion(
        cred["pub_b64"].as_str().unwrap_or_default(),
        cred["sign_count"].as_u64().unwrap_or(0) as u32,
        auth_b64,
        cd_b64,
        sig_b64,
        challenge,
        origin,
        rp_id,
    )
}

/// Der Client liefert den lokal geöffneten HW-Shard als `{x, y_b64}`.
pub fn hw_shard(req: &Value) -> Result<Value, String> {
    let hw = req
        .get("shamir_hw")
        .filter(|v| v.get("x").and_then(|x| x.as_u64()).is_some())
        .filter(|v| v.get("y_b64").and_then(|y| y.as_str()).is_some())
        .cloned();
    hw.ok_or_else(|| "webauthn-verify: shamir_hw fehlt (Client muss Shard lokal öffnen)".into())
}

pub struct WebauthnVerifyNode {
    name: String,
    s3_config: String,
    addr_path: String,
    challenge_dir: String,
    rp_id: String,
    origin: String,
}

#[async_trait::async_trait]
impl NodeExecutor for WebauthnVerifyNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let Some(user) = text(req, "user").map(|s| s.to_string()) else {
            return Ok(err(&msg, "webauthn-verify: user fehlt"));
        };
        let Some(addr) = text(&msg.payload, &self.addr_path).map(|s| s.to_string()) else {
            return Ok(err(&msg, "webauthn-verify: addr_user fehlt (kv3-adresse zuerst)"));
        };
        let Some(challenge) = text(req, "challenge").map(|s| s.to_string()) else {
            return Ok(err(&msg, "webauthn-verify: challenge fehlt"));
        };
        let Some(cred_id) = text(req, "credentialId").map(|s| s.to_string()) else {
            return Ok(err(&msg, "webauthn-verify: credentialId fehlt"));
        };
        let shamir_hw = match hw_shard(req) {
            Ok(h) => h,
            Err(e) => return Ok(err(&msg, e)),
        };
        if let Err(e) = setup_challenge::verbrauche(&self.challenge_dir, &user, &challenge) {
            return Ok(err(&msg, format!("webauthn-verify challenge: {e}")));
        }
        let cfg = match reg::cfg_aus(&self.s3_config, req) {
            Ok(c) => c,
            Err(e) => return Ok(err(&msg, format!("webauthn-verify s3: {e}"))),
        };
        let key = credential_registry_key(&addr);
        let raw = match cfg.get(&key).await {
            Ok(d) => d,
            Err(e) => return Ok(err(&msg, format!("webauthn-verify registry {key}: {e}"))),
        };
        let mut registry: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => return Ok(err(&msg, format!("webauthn-verify registry JSON: {e}"))),
        };
        let cred = registry["credentials"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|c| c["credential_id"].as_str() == Some(cred_id.as_str()))
            })
            .cloned();
        let Some(cred) = cred else {
            return Ok(err(&msg, "webauthn-verify: Credential nicht registriert"));
        };
        let count = match pruefe_credential(
            &cred,
            text(req, "authenticatorData").unwrap_or_default(),
            text(req, "clientDataJSON").unwrap_or_default(),
            text(req, "signature").unwrap_or_default(),
            &challenge,
            &self.origin,
            &self.rp_id,
        ) {
            Ok(c) => c,
            Err(e) => return Ok(err(&msg, format!("webauthn-verify: {e}"))),
        };
        if let Some(arr) = registry["credentials"].as_array_mut() {
            for c in arr.iter_mut() {
                if c["credential_id"].as_str() == Some(cred_id.as_str()) {
                    c["sign_count"] = json!(count);
                }
            }
        }
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        let data = serde_json::to_vec_pretty(&registry).map_err(|e| {
            crate::error::Z8Error::Internal(format!("webauthn-verify registry encode: {e}"))
        })?;
        if let Err(e) = cfg.put(&key, data).await {
            return Ok(err(&msg, format!("webauthn-verify registry save: {e}")));
        }
        let mut out = msg.payload.clone();
        if let Some(o) = out.as_object_mut() {
            if let Some(body) = o
                .get_mut("req")
                .and_then(|r| r.get_mut("body"))
                .and_then(|b| b.as_object_mut())
            {
                body.remove("shamir_hw");
            }
            o.insert(
                "hw_block".into(),
                json!({ "shamir_hw": shamir_hw, "quelle": "webauthn-credential" }),
            );
            o.insert(
                "webauthn_assertion".into(),
                json!({
                    "ok": true,
                    "user": user,
                    "credential_id": cred_id,
                    "sign_count": count,
                    "key_type": "webauthn-software",
                }),
            );
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "addrPath" => addr_path: str,
            "challengeDir" => challenge_dir: str,
            "rpId" => rp_id: str,
            "origin" => origin: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "webauthn-verify"
    }
}

node_factory!(WebauthnVerifyNodeFactory, WebauthnVerifyNode, "webauthn-verify", {
    name: "webauthn-verify".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    addr_path: "addr_user".to_string(),
    challenge_dir: "/data/z8run/login-challenges".to_string(),
    rp_id: "localhost".to_string(),
    origin: "http://localhost:7700".to_string(),
});

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    fn software_credential() -> (Value, p256::SecretKey, Vec<u8>, String, String) {
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            p256::PublicKey::from(secret.public_key()).to_sec1_bytes(),
        );
        let cred = json!({
            "credential_id": "cred-1",
            "pub_b64": pub_b64,
            "pqc_pub_b64": "fake-ek",
            "sign_count": 1,
            "key_type": "webauthn-software",
        });
        (cred, secret, b"cred-1".to_vec(), "localhost".into(), "http://localhost:7700".into())
    }

    fn assertion(
        secret: &p256::SecretKey,
        challenge: &str,
        count: u32,
        rp: &str,
        origin: &str,
    ) -> (String, String, String) {
        use sha2::Digest;
        let mut auth = sha2::Sha256::digest(rp.as_bytes()).to_vec();
        auth.push(0x01);
        auth.extend_from_slice(&count.to_be_bytes());
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#
        );
        let mut signed = auth.clone();
        signed.extend_from_slice(&sha2::Sha256::digest(cd.as_bytes()));
        let key = p256::ecdsa::SigningKey::from(secret);
        let sig: p256::ecdsa::Signature = key.sign(&signed);
        let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b);
        (b64(&auth), b64(cd.as_bytes()), b64(sig.to_der().as_bytes()))
    }

    #[test]
    fn gueltige_assertion_liefert_shamir_hw() {
        let (cred, secret, _, rp, origin) = software_credential();
        let ch = "challenge-ok";
        let (a, cd, sig) = assertion(&secret, ch, 2, &rp, &origin);
        let count = pruefe_credential(&cred, &a, &cd, &sig, ch, &origin, &rp).unwrap();
        assert_eq!(count, 2);
        let req = json!({"shamir_hw": {"x": 2, "y_b64": "QUJD"}});
        assert_eq!(hw_shard(&req).unwrap()["x"], 2);
        assert!(hw_shard(&json!({})).is_err());
    }

    #[test]
    fn replay_counter_und_falsche_signatur_werden_abgewiesen() {
        let (cred, secret, _, rp, origin) = software_credential();
        let ch = "challenge-x";
        let (a, cd, sig) = assertion(&secret, ch, 2, &rp, &origin);
        // Replay: gespeicherter Counter ist bereits 2
        let mut replay = cred.clone();
        replay["sign_count"] = json!(2);
        assert!(pruefe_credential(&replay, &a, &cd, &sig, ch, &origin, &rp).is_err());
        // Signatur 1 Byte geflippt
        let mut raw = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &sig,
        )
        .unwrap();
        raw[0] ^= 1;
        let bad = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &raw,
        );
        assert!(pruefe_credential(&cred, &a, &cd, &bad, ch, &origin, &rp).is_err());
        // falscher Origin
        assert!(pruefe_credential(&cred, &a, &cd, &sig, ch, "http://evil", &rp).is_err());
    }

    #[test]
    fn hardware_ohne_pqc_bleibt_beim_pem_weg() {
        let (mut cred, secret, _, rp, origin) = software_credential();
        cred["key_type"] = json!("webauthn-hardware");
        let ch = "challenge-hw";
        let (a, cd, sig) = assertion(&secret, ch, 2, &rp, &origin);
        let e = pruefe_credential(&cred, &a, &cd, &sig, ch, &origin, &rp).unwrap_err();
        assert!(e.contains("PEM-Weg"));
    }
}
