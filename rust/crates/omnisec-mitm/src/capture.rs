//! Structured capture types for MITM observations.
//!
//! These mirror what each protocol handler in this crate (`dns`, `ssl`,
//! `obfs`) already computes while pushing bytes, so higher layers (see
//! `omnisec-ncer-parse-net`) can convert real observations into NCER typed
//! events instead of only reading `tracing` log lines.
//!
//! `TlsHandshakeCapture` is the one exception: this crate does not parse TLS
//! ClientHello/SNI/cipher suites/certificates anywhere today (`ssl.rs`'s
//! `CONNECT` handler returns `501 Not Implemented` rather than intercepting
//! TLS), so there is no live site that produces one. It's defined here so the
//! schema is stable now; construction can be wired in once TLS interception
//! exists.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use omnisec_json::{FromJson, ToJson};

/// A captured outbound HTTP request, as observed by `ssl::run_ssl_strip_proxy`.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct HttpRequestCapture {
    /// Unix epoch milliseconds when the request was observed.
    pub timestamp_ms: u64,
    /// HTTP method, e.g. `"GET"`.
    pub method: String,
    /// Request target as seen on the request line (path or absolute URL).
    pub url: String,
    /// Request headers.
    pub headers: BTreeMap<String, String>,
}

/// A captured HTTP response, as observed by `ssl::run_ssl_strip_proxy`.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct HttpResponseCapture {
    /// Unix epoch milliseconds when the response was observed.
    pub timestamp_ms: u64,
    /// HTTP status code, e.g. `200`.
    pub status: u16,
    /// Response headers.
    pub headers: BTreeMap<String, String>,
    /// Method of the request this response answers, if known. The proxy
    /// handles one request/response per connection synchronously, so this
    /// is populated from the request it just forwarded.
    pub request_method: Option<String>,
    /// URL of the request this response answers, if known. See
    /// `request_method`.
    pub request_url: Option<String>,
}

/// A captured DNS query and its (possibly spoofed) answer, as observed by
/// `dns::run_dns_spoof_server`.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct DnsQueryCapture {
    /// Unix epoch milliseconds when the query was observed.
    pub timestamp_ms: u64,
    /// Queried domain name.
    pub query_name: String,
    /// DNS QTYPE, e.g. `1` for an A record.
    pub record_type: u16,
    /// IPv4 addresses returned in the response, if any.
    pub response_ips: Vec<Ipv4Addr>,
}

/// A captured TLS handshake.
///
/// As of the network-interception overhaul this is produced live by
/// `ssl.rs`'s `CONNECT` handler, which dissects the client's ClientHello with
/// `omnisec_capture::parse_client_hello` before tunnelling the connection. The
/// `ja3`, `ja3_hash` and `alpn` fields were added afterwards and carry
/// `#[json(default)]` so pre-overhaul capture JSON (which lacked them) still
/// deserialises cleanly — the Go side decodes `tls_handshakes` into an
/// ignoring struct, so no Go change is required for the new fields.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct TlsHandshakeCapture {
    /// Unix epoch milliseconds when the handshake was observed.
    pub timestamp_ms: u64,
    /// Server Name Indication offered by the client.
    pub sni: String,
    /// Negotiated (or offered) cipher suite name.
    pub cipher_suite: String,
    /// Hex-encoded fingerprints of the certificate chain, leaf first.
    pub cert_chain_fingerprints: Vec<String>,
    /// Raw JA3 string (`ver,ciphers,exts,curves,formats`).
    #[json(default)]
    pub ja3: String,
    /// MD5 of `ja3`, hex-encoded — the canonical JA3 client fingerprint.
    #[json(default)]
    pub ja3_hash: String,
    /// ALPN protocol identifiers the client offered (e.g. `["h2", "http/1.1"]`).
    #[json(default)]
    pub alpn: Vec<String>,
}

/// A captured network flow summary, as observed by `obfs::run_obfuscated_proxy`.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct FlowSummaryCapture {
    /// Unix epoch milliseconds when the flow ended.
    pub timestamp_ms: u64,
    /// Client-side address.
    pub src_ip: IpAddr,
    /// Client-side port.
    pub src_port: u16,
    /// Upstream address.
    pub dst_ip: IpAddr,
    /// Upstream port.
    pub dst_port: u16,
    /// Total bytes transferred in both directions.
    pub bytes: u64,
    /// Flow duration in milliseconds.
    pub duration_ms: u64,
    /// Transport protocol, e.g. `"tcp"`.
    pub protocol: String,
}

/// A batch of everything captured during a MITM session. A single
/// `MitmCapture` can hold zero or more of each kind; `omnisec-ncer-parse-net`
/// converts it into one `TypedEvent` per populated item.
#[derive(Debug, Clone, PartialEq, Default, ToJson, FromJson)]
pub struct MitmCapture {
    /// Captured HTTP requests.
    pub http_requests: Vec<HttpRequestCapture>,
    /// Captured HTTP responses.
    pub http_responses: Vec<HttpResponseCapture>,
    /// Captured DNS queries.
    pub dns_queries: Vec<DnsQueryCapture>,
    /// Captured TLS handshakes.
    pub tls_handshakes: Vec<TlsHandshakeCapture>,
    /// Captured flow summaries.
    pub flow_summaries: Vec<FlowSummaryCapture>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_capture_round_trips_through_json() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "example.com".to_string());
        let capture = HttpRequestCapture {
            timestamp_ms: 1_752_400_000_000,
            method: "GET".to_string(),
            url: "/index.html".to_string(),
            headers,
        };
        let json = omnisec_json::to_json_string(&capture);
        let decoded: HttpRequestCapture = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, capture);
    }

    #[test]
    fn http_response_capture_round_trips_through_json() {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let capture = HttpResponseCapture {
            timestamp_ms: 1_752_400_000_000,
            status: 200,
            headers,
            request_method: Some("GET".to_string()),
            request_url: Some("/index.html".to_string()),
        };
        let json = omnisec_json::to_json_string(&capture);
        let decoded: HttpResponseCapture = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, capture);
    }

    #[test]
    fn dns_query_capture_round_trips_through_json() {
        let capture = DnsQueryCapture {
            timestamp_ms: 1_752_400_000_000,
            query_name: "example.com".to_string(),
            record_type: 1,
            response_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
        };
        let json = omnisec_json::to_json_string(&capture);
        let decoded: DnsQueryCapture = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, capture);
    }

    #[test]
    fn tls_handshake_capture_round_trips_through_json() {
        let capture = TlsHandshakeCapture {
            timestamp_ms: 1_752_400_000_000,
            sni: "example.com".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            cert_chain_fingerprints: vec!["deadbeef".to_string()],
            ja3: "771,4865,0-16,,".to_string(),
            ja3_hash: "0123456789abcdef0123456789abcdef".to_string(),
            alpn: vec!["h2".to_string()],
        };
        let json = omnisec_json::to_json_string(&capture);
        let decoded: TlsHandshakeCapture = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, capture);
    }

    #[test]
    fn tls_handshake_capture_decodes_legacy_json_without_ja3_fields() {
        // Pre-overhaul JSON lacked ja3/ja3_hash/alpn; serde(default) must fill.
        let legacy = r#"{
            "timestamp_ms": 1,
            "sni": "example.com",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "cert_chain_fingerprints": []
        }"#;
        let decoded: TlsHandshakeCapture = omnisec_json::from_json_str(legacy).unwrap();
        assert_eq!(decoded.ja3, "");
        assert!(decoded.alpn.is_empty());
    }

    #[test]
    fn flow_summary_capture_round_trips_through_json() {
        let capture = FlowSummaryCapture {
            timestamp_ms: 1_752_400_000_000,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 51234,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            bytes: 4096,
            duration_ms: 250,
            protocol: "tcp".to_string(),
        };
        let json = omnisec_json::to_json_string(&capture);
        let decoded: FlowSummaryCapture = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, capture);
    }

    #[test]
    fn mitm_capture_round_trips_with_mixed_population() {
        let capture = MitmCapture {
            http_requests: vec![HttpRequestCapture {
                timestamp_ms: 1,
                method: "GET".to_string(),
                url: "/".to_string(),
                headers: BTreeMap::new(),
            }],
            http_responses: vec![],
            dns_queries: vec![DnsQueryCapture {
                timestamp_ms: 2,
                query_name: "example.com".to_string(),
                record_type: 1,
                response_ips: vec![],
            }],
            tls_handshakes: vec![],
            flow_summaries: vec![],
        };
        let json = omnisec_json::to_json_string(&capture);
        let decoded: MitmCapture = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, capture);
    }

    #[test]
    fn mitm_capture_default_is_empty() {
        let capture = MitmCapture::default();
        assert!(capture.http_requests.is_empty());
        assert!(capture.http_responses.is_empty());
        assert!(capture.dns_queries.is_empty());
        assert!(capture.tls_handshakes.is_empty());
        assert!(capture.flow_summaries.is_empty());
    }
}
