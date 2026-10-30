//! Port-independent (nDPI-style) protocol classification.
//!
//! The old proxy sniffed only the first 5 bytes and knew three things apart:
//! TLS, HTTP/2 preface, and "custom binary". This classifier works from the
//! reassembled stream bytes rather than the port number, so a game speaking
//! HTTP on port 8443 or TLS on port 4000 is still recognised, and it covers a
//! wider protocol set. It returns the *most specific* protocol it can prove
//! from the bytes, falling back to [`Protocol::Unknown`].

use omnisec_json::{FromJson, ToJson};

use crate::frame::Transport;
use crate::tls::parse_client_hello;

/// A recognised application-layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Protocol {
    /// HTTP/1.x request or response.
    Http1,
    /// HTTP/2 connection preface (`PRI * HTTP/2.0...`).
    Http2,
    /// A WebSocket upgrade handshake (HTTP `Upgrade: websocket`).
    WebSocket,
    /// A TLS record (handshake or application data).
    Tls,
    /// A DNS message (query or response).
    Dns,
    /// An SSH transport banner.
    Ssh,
    /// Bytes were present but matched no known signature.
    Unknown,
}

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// Classifies a stream prefix. `transport` disambiguates cases that only make
/// sense over one transport (e.g. a bare DNS message over UDP).
#[must_use]
pub fn classify(payload: &[u8], transport: Transport) -> Protocol {
    if payload.is_empty() {
        return Protocol::Unknown;
    }

    // HTTP/2 has a fixed 24-byte connection preface — check it before HTTP/1.
    if payload.starts_with(&HTTP2_PREFACE[..payload.len().min(HTTP2_PREFACE.len())])
        && payload.len() >= 4
        && payload.starts_with(b"PRI ")
    {
        return Protocol::Http2;
    }

    // TLS record: content type 20..=23, legacy version 0x03xx.
    if payload.len() >= 3
        && matches!(payload[0], 0x14..=0x17)
        && payload[1] == 0x03
        && payload[2] <= 0x04
    {
        return Protocol::Tls;
    }

    // SSH transport banner.
    if payload.starts_with(b"SSH-") {
        return Protocol::Ssh;
    }

    // HTTP/1.x — a request line method or a status line, then look for an
    // Upgrade: websocket header to refine to WebSocket.
    if is_http1(payload) {
        if header_has_websocket_upgrade(payload) {
            return Protocol::WebSocket;
        }
        return Protocol::Http1;
    }

    // DNS over UDP: 12-byte header with a sane question count and reserved bits.
    if transport == Transport::Udp && looks_like_dns(payload) {
        return Protocol::Dns;
    }

    Protocol::Unknown
}

fn is_http1(payload: &[u8]) -> bool {
    if payload.starts_with(b"HTTP/1.") {
        return true;
    }
    HTTP_METHODS.iter().any(|m| payload.starts_with(m))
}

fn header_has_websocket_upgrade(payload: &[u8]) -> bool {
    // Only scan the header block (up to the blank line), case-insensitively.
    let end = find_subsequence(payload, b"\r\n\r\n").unwrap_or(payload.len());
    let head = &payload[..end];
    contains_ci(head, b"upgrade:") && contains_ci(head, b"websocket")
}

fn looks_like_dns(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    // Z (reserved) bits must be zero; opcode must be a defined value (0,1,2,4,5).
    if flags & 0x0070 != 0 {
        return false;
    }
    let opcode = (flags >> 11) & 0x0f;
    if !matches!(opcode, 0 | 1 | 2 | 4 | 5) {
        return false;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    // At least one question, but not an absurd number for a single datagram.
    (1..=64).contains(&qdcount)
}

/// Extracts the SNI from a TLS ClientHello prefix, if this stream is a
/// parseable handshake. Convenience for callers that classified [`Protocol::Tls`].
#[must_use]
pub fn tls_sni(payload: &[u8]) -> Option<String> {
    parse_client_hello(payload).and_then(|info| info.sni)
}

fn contains_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|w| {
        w.iter()
            .zip(needle_lower)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http1_request_regardless_of_port() {
        assert_eq!(
            classify(b"GET /path HTTP/1.1\r\nHost: x\r\n\r\n", Transport::Tcp),
            Protocol::Http1
        );
        assert_eq!(
            classify(b"HTTP/1.1 200 OK\r\n\r\n", Transport::Tcp),
            Protocol::Http1
        );
    }

    #[test]
    fn detects_http2_preface() {
        assert_eq!(classify(HTTP2_PREFACE, Transport::Tcp), Protocol::Http2);
    }

    #[test]
    fn detects_websocket_upgrade() {
        let req =
            b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(classify(req, Transport::Tcp), Protocol::WebSocket);
    }

    #[test]
    fn detects_tls_record() {
        assert_eq!(
            classify(&[0x16, 0x03, 0x01, 0x00, 0x10], Transport::Tcp),
            Protocol::Tls
        );
        assert_eq!(
            classify(&[0x17, 0x03, 0x03, 0x00, 0x10], Transport::Tcp),
            Protocol::Tls
        );
    }

    #[test]
    fn detects_ssh_banner() {
        assert_eq!(
            classify(b"SSH-2.0-OpenSSH_9.0\r\n", Transport::Tcp),
            Protocol::Ssh
        );
    }

    #[test]
    fn detects_dns_over_udp_only() {
        // id=0x1234, flags=0x0100 (standard query, RD), qd=1.
        let dns = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert_eq!(classify(&dns, Transport::Udp), Protocol::Dns);
        // Same bytes over TCP are not classified as DNS by this heuristic.
        assert_eq!(classify(&dns, Transport::Tcp), Protocol::Unknown);
    }

    #[test]
    fn unknown_for_random_bytes() {
        assert_eq!(
            classify(&[0xde, 0xad, 0xbe, 0xef], Transport::Tcp),
            Protocol::Unknown
        );
        assert_eq!(classify(&[], Transport::Tcp), Protocol::Unknown);
    }
}
