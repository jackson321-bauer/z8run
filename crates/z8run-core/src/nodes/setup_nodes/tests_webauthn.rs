//! WebAuthn-Software-Authenticator-Gegenprobe (CBOR/ES256).

fn cb_head(major: u8, n: usize) -> Vec<u8> {
    if n < 24 {
        vec![(major << 5) | n as u8]
    } else if n < 256 {
        vec![(major << 5) | 24, n as u8]
    } else {
        let mut v = vec![(major << 5) | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    }
}
fn cb_bytes(b: &[u8]) -> Vec<u8> {
    let mut v = cb_head(2, b.len());
    v.extend_from_slice(b);
    v
}
fn cb_text(s: &str) -> Vec<u8> {
    let mut v = cb_head(3, s.len());
    v.extend_from_slice(s.as_bytes());
    v
}
fn cb_int(i: i64) -> Vec<u8> {
    if i >= 0 { cb_head(0, i as usize) } else { cb_head(1, (-1 - i) as usize) }
}

#[test]
fn webauthn_registrierung_und_assertion_mit_software_authenticator() {
    use super::setup_webauthn::{b64url, verarbeite_registrierung};
    use super::setup_webauthn_assert::pruefe_assertion;
    use p256::ecdsa::signature::Signer;
    use sha2::Digest;

    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pub_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        p256::PublicKey::from(secret.public_key()).to_sec1_bytes(),
    );
    let rp = "localhost";
    let origin = "http://localhost:7700";
    let challenge = b64url(b"challenge-123");
    let cred_id = vec![9u8; 16];
    let sec1 = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, &pub_b64).unwrap();
    let mut cose = vec![0xa5];
    cose.extend(cb_int(1)); cose.extend(cb_int(2));
    cose.extend(cb_int(3)); cose.extend(cb_int(-7));
    cose.extend(cb_int(-1)); cose.extend(cb_int(1));
    cose.extend(cb_int(-2)); cose.extend(cb_bytes(&sec1[1..33]));
    cose.extend(cb_int(-3)); cose.extend(cb_bytes(&sec1[33..65]));
    let rp_hash = sha2::Sha256::digest(rp.as_bytes());
    let mut auth = rp_hash.to_vec();
    auth.push(0x41);
    auth.extend_from_slice(&1u32.to_be_bytes());
    auth.extend_from_slice(&[0u8; 16]);
    auth.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&cred_id);
    auth.extend_from_slice(&cose);
    let mut att = vec![0xa3];
    att.extend(cb_text("fmt")); att.extend(cb_text("none"));
    att.extend(cb_text("attStmt")); att.push(0xa0);
    att.extend(cb_text("authData")); att.extend(cb_bytes(&auth));
    let cd = format!(r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{origin}"}}"#);
    let cred = verarbeite_registrierung(
        &b64url(cd.as_bytes()), &b64url(&att), &challenge, origin, rp, "anna",
    ).unwrap();
    assert_eq!(cred["credential_id"], b64url(&cred_id));
    assert_eq!(cred["pub_b64"], pub_b64);

    let challenge2 = b64url(b"challenge-456");
    let mut auth2 = sha2::Sha256::digest(rp.as_bytes()).to_vec();
    auth2.push(0x01);
    auth2.extend_from_slice(&2u32.to_be_bytes());
    let cd2 = format!(r#"{{"type":"webauthn.get","challenge":"{challenge2}","origin":"{origin}"}}"#);
    let mut signed = auth2.clone();
    signed.extend_from_slice(&sha2::Sha256::digest(cd2.as_bytes()));
    let key = p256::ecdsa::SigningKey::from(&secret);
    let sig: p256::ecdsa::Signature = key.sign(&signed);
    let sig_b64 = b64url(sig.to_der().as_bytes());
    let count = pruefe_assertion(
        &pub_b64, 1, &b64url(&auth2), &b64url(cd2.as_bytes()), &sig_b64,
        &challenge2, origin, rp,
    ).unwrap();
    assert_eq!(count, 2);
    assert!(pruefe_assertion(
        &pub_b64, 2, &b64url(&auth2), &b64url(cd2.as_bytes()), &sig_b64,
        &challenge2, origin, rp,
    ).is_err());
}
