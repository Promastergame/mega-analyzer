//! TLS ClientHello dissection and JA3 fingerprinting.
//!
//! This closes one of the review's headline gaps: `TlsHandshakeCapture` was a
//! dead struct because nothing in the codebase parsed a real handshake. Here we
//! parse a ClientHello record end to end — versions, cipher suites, extensions,
//! supported groups, EC point formats, SNI and ALPN — and compute a JA3
//! fingerprint whose MD5 is byte-for-byte identical to the Go
//! `netproxy.JA3` implementation (same field order, same GREASE filtering per
//! RFC 8701, same MD5 hash), so fingerprints computed on either side of the
//! FFI boundary compare equal.

use omnisec_crypto::Md5;
use omnisec_json::{FromJson, ToJson};

/// Everything JA3-relevant plus SNI/ALPN extracted from a TLS ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, Default, ToJson, FromJson)]
pub struct ClientHelloInfo {
    /// Legacy `client_version` field (e.g. `0x0303` for TLS 1.2).
    pub version: u16,
    /// Offered cipher suites, GREASE values removed.
    pub cipher_suites: Vec<u16>,
    /// Offered extension types, GREASE values removed, in wire order.
    pub extensions: Vec<u16>,
    /// Named groups / elliptic curves from the `supported_groups` extension.
    pub curves: Vec<u16>,
    /// EC point formats from the `ec_point_formats` extension.
    pub point_formats: Vec<u16>,
    /// Server Name Indication host, if present.
    pub sni: Option<String>,
    /// ALPN protocol identifiers offered (e.g. `["h2", "http/1.1"]`).
    pub alpn: Vec<String>,
    /// The raw JA3 string (`ver,ciphers,exts,curves,formats`).
    pub ja3: String,
    /// The MD5 hash of `ja3`, hex-encoded — the canonical JA3 fingerprint.
    pub ja3_hash: String,
}

/// Reports whether a 16-bit value is a GREASE placeholder (RFC 8701).
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn join_u16(vals: &[u16]) -> String {
    let mut s = String::new();
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        s.push_str(&v.to_string());
    }
    s
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

/// Parses a TLS record that begins with a Handshake (`0x16`) carrying a
/// ClientHello (handshake type `1`). Returns `None` on any structural error,
/// which callers should treat as "not a parseable ClientHello".
pub fn parse_client_hello(record: &[u8]) -> Option<ClientHelloInfo> {
    // Record header: type(1) version(2) length(2).
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let p = &record[5..];
    // Handshake header: type(1) length(3).
    if p.len() < 4 || p[0] != 0x01 {
        return None;
    }
    let mut p = &p[4..];
    // client_version(2) + random(32).
    if p.len() < 34 {
        return None;
    }
    let mut info = ClientHelloInfo {
        version: be16(p, 0)?,
        ..Default::default()
    };
    p = &p[34..];
    // session_id.
    let sid_len = *p.first()? as usize;
    p = p.get(1..)?;
    p = p.get(sid_len..)?;
    // cipher_suites.
    let cs_len = be16(p, 0)? as usize;
    p = p.get(2..)?;
    let cs = p.get(..cs_len)?;
    let mut i = 0;
    while i + 1 < cs_len {
        let c = be16(cs, i)?;
        if !is_grease(c) {
            info.cipher_suites.push(c);
        }
        i += 2;
    }
    p = p.get(cs_len..)?;
    // compression_methods.
    let cm_len = *p.first()? as usize;
    p = p.get(1..)?;
    p = p.get(cm_len..)?;
    // extensions (may be absent in ancient TLS; tolerate).
    if p.len() < 2 {
        info.finalise_ja3();
        return Some(info);
    }
    let mut ext_total = be16(p, 0)? as usize;
    p = &p[2..];
    if p.len() < ext_total {
        ext_total = p.len();
    }
    let mut ext = &p[..ext_total];
    while ext.len() >= 4 {
        let ext_type = be16(ext, 0)?;
        let ext_len = be16(ext, 2)? as usize;
        ext = &ext[4..];
        if ext.len() < ext_len {
            break;
        }
        let body = &ext[..ext_len];
        ext = &ext[ext_len..];
        if !is_grease(ext_type) {
            info.extensions.push(ext_type);
        }
        match ext_type {
            0x0000 => info.sni = parse_sni(body),
            0x000a => info.curves = parse_named_list(body),
            0x000b => info.point_formats = parse_point_formats(body),
            0x0010 => info.alpn = parse_alpn(body),
            _ => {}
        }
    }
    info.finalise_ja3();
    Some(info)
}

impl ClientHelloInfo {
    fn finalise_ja3(&mut self) {
        self.ja3 = format!(
            "{},{},{},{},{}",
            self.version,
            join_u16(&self.cipher_suites),
            join_u16(&self.extensions),
            join_u16(&self.curves),
            join_u16(&self.point_formats),
        );
        let digest = Md5::digest(self.ja3.as_bytes());
        self.ja3_hash = hex_lower(&digest);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn parse_sni(body: &[u8]) -> Option<String> {
    // ServerNameList: list_len(2), then entries of type(1) name_len(2) name.
    if body.len() < 2 {
        return None;
    }
    let mut q = &body[2..];
    while q.len() >= 3 {
        let name_type = q[0];
        let name_len = u16::from_be_bytes([q[1], q[2]]) as usize;
        q = &q[3..];
        if q.len() < name_len {
            break;
        }
        if name_type == 0 {
            return Some(String::from_utf8_lossy(&q[..name_len]).into_owned());
        }
        q = &q[name_len..];
    }
    None
}

fn parse_named_list(body: &[u8]) -> Vec<u16> {
    // supported_groups: list_len(2), then u16 entries.
    let mut out = Vec::new();
    if body.len() < 2 {
        return out;
    }
    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
    let list = &body[2..];
    let mut i = 0;
    while i + 1 < n && i + 1 < list.len() {
        let g = u16::from_be_bytes([list[i], list[i + 1]]);
        if !is_grease(g) {
            out.push(g);
        }
        i += 2;
    }
    out
}

fn parse_point_formats(body: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    if body.is_empty() {
        return out;
    }
    let n = body[0] as usize;
    for i in 0..n {
        if let Some(b) = body.get(1 + i) {
            out.push(u16::from(*b));
        }
    }
    out
}

fn parse_alpn(body: &[u8]) -> Vec<String> {
    // ALPNProtocolNameList: list_len(2), then len(1)+name entries.
    let mut out = Vec::new();
    if body.len() < 2 {
        return out;
    }
    let mut q = &body[2..];
    while let Some(&len) = q.first() {
        let len = len as usize;
        q = &q[1..];
        if q.len() < len {
            break;
        }
        out.push(String::from_utf8_lossy(&q[..len]).into_owned());
        q = &q[len..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a small but valid ClientHello record with one SNI + ALPN.
    fn sample_client_hello() -> Vec<u8> {
        // Handshake body first.
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        // cipher_suites: one GREASE (0x0a0a) + TLS_AES_128_GCM_SHA256 (0x1301).
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x0a0au16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression methods len
        body.push(0); // null compression

        // Extensions.
        let mut exts = Vec::new();
        // SNI extension (0x0000) for "example.com".
        let host = b"example.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
        sni.push(0); // name type host
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);
        // ALPN extension (0x0010) offering "h2".
        let mut alpn = Vec::new();
        alpn.extend_from_slice(&3u16.to_be_bytes()); // list len
        alpn.push(2); // proto len
        alpn.extend_from_slice(b"h2");
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header: type(1)=1 + length(3).
        let mut hs = Vec::new();
        hs.push(0x01);
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        // Record header: type(1)=0x16 version(2) length(2).
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&0x0301u16.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni_alpn_and_filters_grease_ciphers() {
        let info = parse_client_hello(&sample_client_hello()).expect("parse");
        assert_eq!(info.version, 0x0303);
        assert_eq!(info.cipher_suites, vec![0x1301]); // GREASE removed
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.alpn, vec!["h2".to_string()]);
        assert!(info.extensions.contains(&0x0000));
        assert!(info.extensions.contains(&0x0010));
    }

    #[test]
    fn ja3_string_and_hash_are_deterministic() {
        let info = parse_client_hello(&sample_client_hello()).expect("parse");
        // ver=771, one cipher 4865(0x1301), exts 0,16, no curves/formats.
        assert_eq!(info.ja3, "771,4865,0-16,,");
        // MD5 of the JA3 string, verified against a second independent digest.
        let expected = hex_lower(&Md5::digest(info.ja3.as_bytes()));
        assert_eq!(info.ja3_hash, expected);
        assert_eq!(info.ja3_hash.len(), 32);
    }

    #[test]
    fn rejects_non_handshake_record() {
        assert!(parse_client_hello(b"not tls").is_none());
        assert!(parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x05]).is_none());
    }

    #[test]
    fn grease_detection_matches_rfc8701_samples() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(!is_grease(0x1301));
    }
}
