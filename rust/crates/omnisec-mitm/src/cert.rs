//! Minimal in-house X.509 self-signed CA generator (Ed25519, RFC 8410).
//!
//! Replaces `rcgen` + `ring`: we only ever needed "make me a self-signed
//! root CA and hand me the PEM files", so the DER encoder below implements
//! exactly that shape and nothing else.

use omnisec_crypto::ed25519::{self, KeyPair};
use omnisec_json::b64_encode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Pre-encoded DER object identifiers.
mod oid {
    /// commonName (2.5.4.3)
    pub const CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    /// basicConstraints (2.5.29.19)
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];
    /// id-Ed25519 (1.3.101.112)
    pub const ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
}

/// DER length encoding (short form < 128, long form otherwise).
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let significant = &bytes[first..];
        let mut out = vec![0x80 | significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

/// Tag-length-value triple.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    tlv(0x30, &content)
}

/// Positive INTEGER (adds the leading zero byte when the high bit is set).
fn integer(content: &[u8]) -> Vec<u8> {
    let mut body = content.to_vec();
    while body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
        body.remove(0);
    }
    if !body.is_empty() && body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

fn bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0u8]; // zero unused bits
    content.extend_from_slice(data);
    tlv(0x03, &content)
}

fn utf8_string(s: &str) -> Vec<u8> {
    tlv(0x0C, s.as_bytes())
}

fn utc_time(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}

fn boolean_true() -> Vec<u8> {
    vec![0x01, 0x01, 0xFF]
}

/// `days` since the Unix epoch → `YYMMDD000000Z` (UTCTime at midnight UTC).
/// Valid through 2049, well past this CA's 10-year notch.
fn utc_time_from_days(days: i64) -> String {
    // Howard Hinnant's civil_from_days, trimmed to what we need.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:02}{:02}{:02}000000Z", year.rem_euclid(100), m, d)
}

/// Decomposed certificate, so tests (and callers) can verify the signature
/// without a full ASN.1 parser.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Complete DER encoding (SEQUENCE { tbs, alg, sig }).
    pub der: Vec<u8>,
    /// The signed TBSCertificate portion.
    pub tbs: Vec<u8>,
    /// Ed25519 signature over `tbs`.
    pub signature: [u8; 64],
    /// The CA public key.
    pub public: [u8; 32],
}

impl Certificate {
    /// PEM encoding (`-----BEGIN CERTIFICATE-----`).
    #[must_use]
    pub fn pem(&self) -> String {
        pem("CERTIFICATE", &self.der)
    }
}

/// PEM wrap with 64-character base64 lines.
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    let b64 = b64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// X.509 `Name` holding a single commonName RDN.
fn name(common_name: &str) -> Vec<u8> {
    let rdn = sequence(&[oid::CN, &utf8_string(common_name)]);
    let set = tlv(0x31, &rdn); // SET OF AttributeTypeAndValue
    sequence(&[&set])
}

/// Build a self-signed CA certificate (v3, basicConstraints CA:TRUE critical,
/// Ed25519 signature, 10-year validity from now).
#[must_use]
pub fn self_signed_ca(common_name: &str, kp: &KeyPair, serial: &[u8; 16]) -> Certificate {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let now_days = now_secs.div_euclid(86_400);
    let validity = sequence(&[
        &utc_time(&utc_time_from_days(now_days)),
        &utc_time(&utc_time_from_days(now_days + 3_652)),
    ]);

    let sig_alg = sequence(&[oid::ED25519]);
    let spki = sequence(&[&sequence(&[oid::ED25519]), &bit_string(&kp.public)]);

    // basicConstraints: critical, CA=TRUE
    let bc_value = tlv(0x04, &sequence(&[&boolean_true()]));
    let bc = sequence(&[oid::BASIC_CONSTRAINTS, &boolean_true(), &bc_value]);
    let extensions = tlv(0xA3, &sequence(&[&bc]));

    let mut tbs_parts: Vec<Vec<u8>> = Vec::new();
    tbs_parts.push(tlv(0xA0, &integer(&[2]))); // [0] EXPLICIT version v3
    tbs_parts.push(integer(serial));
    tbs_parts.push(sig_alg.clone());
    tbs_parts.push(name(common_name));
    tbs_parts.push(validity.clone());
    tbs_parts.push(name(common_name));
    tbs_parts.push(spki);
    tbs_parts.push(extensions);

    let mut tbs_content = Vec::new();
    for part in &tbs_parts {
        tbs_content.extend_from_slice(part);
    }
    let tbs = tlv(0x30, &tbs_content);

    let signature = ed25519::sign(&kp.seed, &tbs);
    let der = sequence(&[&tbs, &sig_alg, &bit_string(&signature)]);

    Certificate {
        der,
        tbs,
        signature,
        public: kp.public,
    }
}

/// PKCS#8 (RFC 5958) PEM encoding of the Ed25519 private key.
#[must_use]
pub fn private_key_pem(kp: &KeyPair) -> String {
    let alg = sequence(&[oid::ED25519]);
    let version = integer(&[0]);
    let inner = tlv(0x04, &kp.seed); // privateKey OCTET STRING = raw seed
    let mut content = Vec::new();
    content.extend_from_slice(&version);
    content.extend_from_slice(&alg);
    content.extend_from_slice(&tlv(0x04, &inner));
    let pkcs8 = tlv(0x30, &content);
    pem("PRIVATE KEY", &pkcs8)
}

/// One-shot: fresh keypair + self-signed CA certificate.
#[must_use]
pub fn generate_ca(common_name: &str) -> std::io::Result<(KeyPair, Certificate)> {
    let kp = KeyPair::from_seed(omnisec_crypto::entropy_seed()?);
    let serial = {
        let seed = omnisec_crypto::entropy_seed()?;
        let mut s = [0u8; 16];
        s.copy_from_slice(&seed[..16]);
        s[0] &= 0x7F; // keep the INTEGER positive
        s
    };
    let cert = self_signed_ca(common_name, &kp, &serial);
    Ok((kp, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_length_encoding_shapes() {
        assert_eq!(der_len(5), vec![5]);
        assert_eq!(der_len(127), vec![127]);
        assert_eq!(der_len(128), vec![0x81, 128]);
        assert_eq!(der_len(300), vec![0x82, 1, 44]);
    }

    #[test]
    fn utc_time_formats_dates() {
        assert_eq!(utc_time_from_days(0), "700101000000Z");
        // 2026-09-14 is day 20610 of the Unix epoch.
        assert_eq!(utc_time_from_days(20_710), "260914000000Z");
    }

    #[test]
    fn certificate_is_well_formed_and_self_consistent() {
        let (kp, cert) = generate_ca("OmniSec MITM Root CA").unwrap();

        // Outer SEQUENCE must span exactly the remaining bytes.
        assert_eq!(cert.der[0], 0x30);
        let len = if cert.der[1] & 0x80 == 0 {
            usize::from(cert.der[1])
        } else {
            let n = usize::from(cert.der[1] & 0x7F);
            let mut v = 0usize;
            for b in &cert.der[2..2 + n] {
                v = (v << 8) | usize::from(*b);
            }
            v
        };
        let header = if cert.der[1] & 0x80 == 0 {
            2
        } else {
            2 + usize::from(cert.der[1] & 0x7F)
        };
        assert_eq!(len, cert.der.len() - header, "DER length must match body");

        // Signature must verify over the TBS with the embedded public key.
        assert!(ed25519::verify(&cert.public, &cert.tbs, &cert.signature));

        // The signature inside the DER must be the one we verified.
        let sig_from_der = &cert.der[cert.der.len() - 64..];
        assert_eq!(sig_from_der, &cert.signature[..]);

        // Version field: A0 03 02 01 02 (v3), right after the variable-length
        // SEQUENCE header of the TBSCertificate.
        let tbs_header = if cert.tbs[1] & 0x80 == 0 {
            2
        } else {
            2 + usize::from(cert.tbs[1] & 0x7F)
        };
        assert_eq!(
            &cert.tbs[tbs_header..tbs_header + 5],
            &[0xA0, 0x03, 0x02, 0x01, 0x02]
        );

        // Deterministic: the key material must be reproducible from the seed.
        let rebuilt = KeyPair::from_seed(kp.seed);
        assert_eq!(rebuilt.public, kp.public);

        // PEM wraps the DER unchanged.
        let pem = cert.pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(omnisec_json::b64_decode(&b64).unwrap(), cert.der);

        // Private key PEM is PKCS#8-shaped.
        let key_pem = private_key_pem(&kp);
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let key_b64: String = key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der_key = omnisec_json::b64_decode(&key_b64).unwrap();
        assert_eq!(&der_key[..4], &[0x30, 0x2E, 0x02, 0x01]); // SEQUENCE, INTEGER 0
        assert!(der_key.ends_with(&kp.seed));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
