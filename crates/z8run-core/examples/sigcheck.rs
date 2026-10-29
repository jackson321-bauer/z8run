use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as U};
use base64::Engine;
use z8run_core::nodes::setup_nodes::setup_crypto as sc;
fn main() {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("/tmp/assert-debug.json").unwrap()).unwrap();
    let b=&v["body"];
    let auth=U.decode(b["authenticatorData"].as_str().unwrap()).unwrap();
    let cd=U.decode(b["clientDataJSON"].as_str().unwrap()).unwrap();
    let sig=U.decode(b["signature"].as_str().unwrap()).unwrap();
    use sha2::Digest;
    let mut signed=auth.clone(); signed.extend_from_slice(&sha2::Sha256::digest(&cd));
    println!("len {} sig {} bool {}", signed.len(), sig.len(), sc::pruefe_signatur(v["pub_b64"].as_str().unwrap(), &signed, &B64.encode(&sig)));
    let raw=B64.decode(v["pub_b64"].as_str().unwrap()).unwrap();
    let pk=p256::PublicKey::from_sec1_bytes(&raw).unwrap();
    let ver=p256::ecdsa::VerifyingKey::from(&pk);
    let s=p256::ecdsa::Signature::from_der(&sig).unwrap();
    use p256::ecdsa::signature::Verifier;
    println!("direct {:?}", ver.verify(&signed,&s));
}
