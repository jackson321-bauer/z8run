//! PQC-TLS (F18/F23): rustls mit aws-lc-rs-Backend. x25519mlkem768 ist
//! hybrid priorisiert; klassische Gruppen bleiben als Fallback. Ohne
//! aws-lc-rs gibt es KEIN ML-KEM — deshalb ist das Backend hart verdrahtet.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::ServerConfig;

/// Fester Provider: aws-lc-rs (ring kann kein ML-KEM).
pub fn provider() -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    // ML-KEM-Hybrid hart nach vorne (Prioritaet, nicht nur Angebot).
    p.kx_groups.sort_by_key(|g| match g.name() {
        rustls::NamedGroup::X25519MLKEM768 => 0,
        _ => 1,
    });
    Arc::new(p)
}

fn load_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Zertifikat-PEM: {e}"))
}

fn load_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    rustls_pemfile::private_key(&mut &*pem)
        .map_err(|e| format!("Key-PEM: {e}"))?
        .ok_or_else(|| "kein Private Key im PEM".to_string())
}

/// Server-Config mit PQC-Prioritaet + klassischem Fallback.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("Protokollversion: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Server-Config: {e}"))?;
    // Hyper bedient HTTP/1.1; h2 wuerde nach ALPN scheitern.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub fn load_server_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<Arc<ServerConfig>, String> {
    let cert = std::fs::read(cert_path)
        .map_err(|e| format!("Zertifikat {}: {e}", cert_path.display()))?;
    let key = std::fs::read(key_path)
        .map_err(|e| format!("Key {}: {e}", key_path.display()))?;
    server_config(&cert, &key)
}

/// Liefert die Namen der angebotenen Gruppen (fuer Log + Assert).
pub fn offered_groups(cfg: &ServerConfig) -> Vec<String> {
    cfg.crypto_provider()
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect()
}

/// Unit-Assert-Basis: Server-Config BIETET die MLKEM-Gruppe an.
pub fn offers_mlkem(cfg: &ServerConfig) -> bool {
    cfg.crypto_provider().kx_groups.iter().any(|g| {
        matches!(
            g.name(),
            rustls::NamedGroup::X25519MLKEM768 | rustls::NamedGroup::secp256r1MLKEM768
        )
    })
}

/// Verhandelte Gruppe eines fertigen TLS-Streams (Score-Daten fuer Botwall).
pub fn negotiated_group_name(
    conn: &rustls::CommonState,
) -> Option<String> {
    conn.negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angebot_enthaelt_mlkem_und_fallback() {
        let groups = provider()
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect::<Vec<_>>();
        println!("KX-Gruppen: {groups:?}");
        assert!(
            groups.iter().any(|g| g == "X25519MLKEM768"),
            "aws-lc-rs bietet X25519MLKEM768 nicht an: {groups:?}"
        );
        assert!(
            groups.iter().any(|g| g == "X25519"),
            "klassischer X25519-Fallback fehlt: {groups:?}"
        );
    }
}
