//! WebAuthn-Assertion (Beweis der Registrierung; Login-Adaptierung folgt
//! in einem eigenen Bauplan). ES256, Signatur über authData||SHA256(clientData).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::Digest;

use super::setup_crypto as sc;
use super::setup_challenge;
use super::setup_io::{body, text};
use super::setup_registry as reg;
use super::setup_webauthn::{b64url_decode, client_data_ok, parse_auth_data};
use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::Z8Result;
use crate::message::FlowMessage;
use crate::node_factory;

/// Reine Assertion-Prüfung (ohne S3) — testbar mit Software-Authenticator.
#[allow(clippy::too_many_arguments)]
pub fn pruefe_assertion(
    pub_b64: &str,
    stored_count: u32,
    auth_b64: &str,
    cd_b64: &str,
    sig_b64: &str,
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> Result<u32, String> {
    let cd = b64url_decode(cd_b64)?;
    client_data_ok(&cd, "webauthn.get", challenge, origin)?;
    let auth_raw = b64url_decode(auth_b64)?;
    let auth = parse_auth_data(&auth_raw)?;
    if auth.rp_id_hash != sha2::Sha256::digest(rp_id.as_bytes()).to_vec() {
        return Err("rpIdHash falsch".into());
    }
    if auth.flags & 0x01 == 0 {
        return Err("User-Presence fehlt".into());
    }
    let cd_hash = sha2::Sha256::digest(&cd);
    let mut signed = auth_raw.clone();
    signed.extend_from_slice(&cd_hash);
    let sig_der = b64url_decode(sig_b64)?;
    if pub_b64.is_empty() {
        return Err("pubkey fehlt".into());
    }
    if !sc::pruefe_signatur(pub_b64, &signed, &B64.encode(&sig_der)) {
        return Err("Signatur falsch".into());
    }
    if stored_count != 0 && auth.sign_count <= stored_count {
        return Err("sign_count nicht gestiegen".into());
    }
    Ok(auth.sign_count)
}

pub struct WebauthnAssertNode {
    name: String,
    s3_config: String,
    registry_key: String,
    master_path: String,
    challenge_dir: String,
}

#[async_trait::async_trait]
impl NodeExecutor for WebauthnAssertNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let req = body(&msg.payload);
        let err = |e: String| vec![msg.derive(msg.source_node, "error", json!({"status": 403, "error": e}))];
        let Some(master_hex) = text(req, &self.master_path) else {
            return Ok(err("webauthn-assert: Setup-Auth fehlt".into()));
        };
        let cfg = match reg::cfg_aus(&self.s3_config, req) {
            Ok(c) => c,
            Err(e) => return Ok(err(format!("webauthn-assert: {e}"))),
        };
        let mut registry = match reg::lade_registry(&cfg, &self.registry_key, master_hex).await {
            Ok(r) => r,
            Err(e) => return Ok(err(format!("webauthn-assert registry: {e}"))),
        };
        let user = text(req, "user").unwrap_or_default().to_string();
        let cred_id = text(req, "credentialId").unwrap_or_default().to_string();
        let rp_id = text(req, "rpId").unwrap_or("localhost").to_string();
        let origin = text(req, "origin").unwrap_or("http://localhost:7700").to_string();
        let Some(challenge) = text(req, "challenge") else {
            return Ok(err("webauthn-assert: challenge fehlt".into()));
        };
        let auth_b64 = text(req, "authenticatorData").unwrap_or_default();
        let cd_b64 = text(req, "clientDataJSON").unwrap_or_default();
        let sig_b64 = text(req, "signature").unwrap_or_default();

        if let Err(e) = setup_challenge::verbrauche(&self.challenge_dir, &user, challenge) {
            return Ok(err(format!("webauthn-assert challenge: {e}")));
        }
        let cred = registry["webauthn"][&user]
            .as_array()
            .and_then(|arr| arr.iter().find(|c| c["credential_id"] == json!(cred_id)))
            .cloned();
        let Some(cred) = cred else {
            return Ok(err("webauthn-assert: Credential nicht registriert".into()));
        };
        let result = pruefe_assertion(
            cred["pub_b64"].as_str().unwrap_or_default(),
            cred["sign_count"].as_u64().unwrap_or(0) as u32,
            auth_b64,
            cd_b64,
            sig_b64,
            challenge,
            &origin,
            &rp_id,
        );
        let count = match result {
            Ok(c) => c,
            Err(e) => return Ok(err(format!("webauthn-assert: {e}"))),
        };
        if !registry["webauthn"].is_object() {
            registry["webauthn"] = json!({});
        }
        if let Some(arr) = registry["webauthn"][&user].as_array_mut() {
            for c in arr.iter_mut() {
                if c["credential_id"] == json!(cred_id) {
                    c["sign_count"] = json!(count);
                }
            }
        }
        registry["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        if let Err(e) = reg::speichere_registry(&cfg, &self.registry_key, master_hex, &registry).await {
            return Ok(err(format!("webauthn-assert save: {e}")));
        }
        let mut out = body(&msg.payload).clone();
        if let Some(o) = out.as_object_mut() {
            o.insert("webauthn_assertion".into(), json!({
                "ok": true, "user": user, "credential_id": cred_id, "sign_count": count,
            }));
        }
        Ok(vec![msg.derive(msg.source_node, "output", out)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "s3Config" => s3_config: str,
            "registryKey" => registry_key: str,
            "masterPath" => master_path: str,
            "challengeDir" => challenge_dir: str,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        Ok(())
    }

    fn node_type(&self) -> &str {
        "webauthn-assert"
    }
}

node_factory!(WebauthnAssertNodeFactory, WebauthnAssertNode, "webauthn-assert", {
    name: "webauthn-assert".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    registry_key: reg::REGISTRY_KEY.to_string(),
    master_path: "setup_master_hex".to_string(),
    challenge_dir: "/data/z8run/setup-challenges".to_string(),
});
