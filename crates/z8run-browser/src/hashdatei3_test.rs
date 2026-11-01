//! NUR Test-Build: erzeugt eine Inline-Welt im /3-Format (b2b + hw-shards)
//! samt v3-Hybrid-Box und ML-KEM-Privatekey. Kein Produktivpfad.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::login;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn hashdatei_bauen(addrs: &[(String, String)], chiffren: &[(String, String)]) -> String {
    let mut s = String::from("Argon2IDHashDatei/3\nwirt_min = 1.4.0\nnr = 1\n\nSecretboxes\nAnfang\n");
    for (a, b) in addrs {
        s.push_str(&format!("{a} = {b}\n"));
    }
    s.push_str("Ende\n\nEncrypted\nAnfang\n");
    for (b, c) in chiffren {
        s.push_str(&format!("{b}\n{c}\n"));
    }
    s.push_str("Ende\n");
    s
}

fn pem_erzeugen() -> (String, p256::PublicKey) {
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let der = secret.to_sec1_der().expect("SEC1");
    let params: [u8; 12] = [0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let content_len = der.len() - 2 + params.len();
    let mut voll = Vec::with_capacity(content_len + 2);
    voll.push(0x30);
    voll.push(content_len as u8);
    voll.extend_from_slice(&der[2..39]);
    voll.extend_from_slice(&params);
    voll.extend_from_slice(&der[39..]);
    let b64 = B64.encode(&voll);
    let mut pem = String::from("-----BEGIN EC PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END EC PRIVATE KEY-----\n");
    (pem, secret.public_key())
}

fn passbox_siegeln(passwort: &str, salt: &str, inhalt: &[u8], aad: &str) -> Value {
    let key = login::argon2_raw(passwort, salt).expect("argon2");
    let nonce: [u8; 12] = rand::random();
    let aead = Aes256Gcm::new((&key).into());
    let ct = aead
        .encrypt(
            (&nonce).into(),
            Payload { msg: inhalt, aad: aad.as_bytes() },
        )
        .expect("aes");
    json!({"nonce": B64.encode(nonce), "box": B64.encode(ct), "aad": aad})
}

pub fn build_test_world_v3(passwort: &str, space: &str, username: &str) -> Value {
    use rand::RngCore;
    let (pem, pubkey) = pem_erzeugen();
    let mut master = [0u8; 32];
    let mut r = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut master);
    rand::rngs::OsRng.fill_bytes(&mut r);
    let y1: Vec<u8> = master.iter().zip(r.iter()).map(|(a, b)| a ^ b).collect();
    let y2: Vec<u8> = master.iter().zip(r.iter()).map(|(a, b)| a ^ rand_mul(*b)).collect();
    let space_salt = crate::hashdatei3::salt_space(space);
    let salt_u = crate::hashdatei3::salt_user(&space_salt, username);
    let user_addr = login::adresse(username, &salt_u).unwrap();
    let payload = json!({
        "shamir_provider": {"x": 1, "y_b64": B64.encode(&y1)},
        "engines": [],
        "buckets": ["demo"],
        "workspace_bucket": "",
    });
    let pbox = passbox_siegeln(passwort, &salt_u, &serde_json::to_vec(&payload).unwrap(), "kv3-user");
    let b2b = hashdatei_bauen(
        &[(user_addr.clone(), "Block-1".into())],
        &[("Block-1".into(), B64.encode(serde_json::to_vec(&pbox).unwrap()))],
    );
    let kemp = crate::umschlag::kem_paar_1024(&mut rand::rngs::OsRng);
    let hwblock = json!({"shamir_hw": {"x": 2, "y_b64": B64.encode(&y2)}});
    let hbox = crate::umschlag::siegeln_v3(
        &mut rand::rngs::OsRng,
        &pubkey,
        &kemp.ek,
        &serde_json::to_vec(&hwblock).unwrap(),
        "kv3-hw",
    )
    .unwrap();
    let pub_b64 = B64.encode(pubkey.to_sec1_bytes());
    let hw = hashdatei_bauen(
        &[(pub_b64, "Block-1".into())],
        &[("Block-1".into(), B64.encode(serde_json::to_vec(&hbox).unwrap()))],
    );
    json!({
        "v3_b2b": b2b,
        "v3_hw": hw,
        "hw_pem": pem,
        "kem_dk_b64": B64.encode(&kemp.dk),
        "password": passwort,
        "space": space,
        "username": username,
        "user_addr": user_addr,
        "master_check_sha256": hex::encode(Sha256::digest(master)),
    })
}

fn rand_mul(b: u8) -> u8 {
    // GF(2^8)-Multiplikation mit 2 (Shamir x=2), wie login.rs gf::mul.
    let mut r = b;
    let hi = r & 0x80;
    r <<= 1;
    if hi != 0 {
        r ^= 0x1b;
    }
    r
}
