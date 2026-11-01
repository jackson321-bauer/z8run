//! SigV4 fuer S3, pure Rust (laeuft nativ und in WASM). Keine Provider-SDKs,
//! keine Presigned-URLs; der Aufrufer liefert Host/Pfad/Header/Zeit.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub struct Signer<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

impl<'a> Signer<'a> {
    pub fn new(access_key: &'a str, secret_key: &'a str, region: &'a str) -> Self {
        Self {
            access_key,
            secret_key,
            region,
            service: "s3",
        }
    }

    pub fn payload_hash(secret: &[u8]) -> String {
        hex::encode(Sha256::digest(secret))
    }

    /// Liefert (Authorization-Header, signierte Header-Liste).
    pub fn authorization(
        &self,
        method: &str,
        host: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        payload_hash: &str,
        amz_date: &str,
    ) -> (String, Vec<(String, String)>) {
        let date = &amz_date[..8];
        let mut hs: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        hs.push(("host".into(), host.into()));
        hs.push(("x-amz-content-sha256".into(), payload_hash.into()));
        hs.push(("x-amz-date".into(), amz_date.into()));
        hs.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_headers: Vec<String> = hs.iter().map(|(k, _)| k.clone()).collect();
        let signed = signed_headers.join(";");
        let canonical = format!(
            "{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}"
        );
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let k_date = hmac(format!("AWS4{}", self.secret_key).as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, self.service.as_bytes());
        let k_signing = hmac(&k_service, b"aws4_request");
        let sig = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
            self.access_key
        );
        let mut out: Vec<(String, String)> = hs
            .into_iter()
            .filter(|(k, _)| k != "host")
            .collect();
        out.push(("authorization".into(), auth));
        (sig, out)
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_beispiel_signatur() {
        let s = Signer::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
        );
        let empty = Signer::payload_hash(b"");
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let (sig, headers) = s.authorization(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            "",
            &[("range".into(), "bytes=0-9".into())],
            &empty,
            "20130524T000000Z",
        );
        assert_eq!(
            sig,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert!(headers.iter().any(|(k, _)| k == "authorization"));
    }
}
