//! Converts `omnisec-mitm` capture data into NCER typed events.
//!
//! This crate is Rust-only: no FFI, no networking, no Go integration. It
//! takes an already-populated `omnisec_mitm::capture::MitmCapture` and
//! produces `omnisec_ncer_types::TypedEvent`s, one per captured item, with a
//! stable content-addressed id derived from the item's canonical JSON —
//! the same "hash the JSON payload" pattern used by the Go adapter's
//! `correlationEventID` (`pkg/ncer/adapter.go`).

use std::collections::BTreeMap;

use omnisec_crypto::Sha256;
use omnisec_json::ToJson;
use omnisec_mitm::capture::{
    DnsQueryCapture, FlowSummaryCapture, HttpRequestCapture, HttpResponseCapture, MitmCapture,
    TlsHandshakeCapture,
};
use omnisec_ncer_types::{EventKind, TypedEvent};

/// Sensor identifier recorded on every event this crate produces.
pub const SENSOR_ID: &str = "mitm-local";

/// Converts a batch of MITM capture data into NCER typed events, one per
/// captured item across all five kinds.
pub fn from_mitm_capture(capture: &MitmCapture) -> Vec<TypedEvent> {
    let mut events = Vec::with_capacity(
        capture.http_requests.len()
            + capture.http_responses.len()
            + capture.dns_queries.len()
            + capture.tls_handshakes.len()
            + capture.flow_summaries.len(),
    );

    events.extend(capture.http_requests.iter().map(http_request_event));
    events.extend(capture.http_responses.iter().map(http_response_event));
    events.extend(capture.dns_queries.iter().map(dns_query_event));
    events.extend(capture.tls_handshakes.iter().map(tls_handshake_event));
    events.extend(capture.flow_summaries.iter().map(flow_summary_event));

    events
}

fn http_request_event(item: &HttpRequestCapture) -> TypedEvent {
    let mut attributes = BTreeMap::new();
    attributes.insert("method".to_string(), item.method.clone());
    attributes.insert("url".to_string(), item.url.clone());
    attributes.insert("headers_json".to_string(), headers_json(&item.headers));

    build_event(
        EventKind::HttpRequest,
        item.timestamp_ms,
        vec![item.url.clone()],
        format!("HTTP {} {}", item.method, item.url),
        attributes,
        item,
    )
}

fn http_response_event(item: &HttpResponseCapture) -> TypedEvent {
    let mut attributes = BTreeMap::new();
    attributes.insert("status".to_string(), item.status.to_string());
    attributes.insert("headers_json".to_string(), headers_json(&item.headers));
    // Carried over from the request this response answers, when known, so
    // downstream reconciliation (omnisec-ncer-reconcile) can correlate a
    // response back to its request by method+url.
    if let Some(method) = &item.request_method {
        attributes.insert("method".to_string(), method.clone());
    }
    if let Some(url) = &item.request_url {
        attributes.insert("url".to_string(), url.clone());
    }

    let subjects = item.request_url.clone().into_iter().collect();

    build_event(
        EventKind::HttpResponse,
        item.timestamp_ms,
        subjects,
        format!("HTTP response {}", item.status),
        attributes,
        item,
    )
}

fn dns_query_event(item: &DnsQueryCapture) -> TypedEvent {
    let response_ips = item
        .response_ips
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut attributes = BTreeMap::new();
    attributes.insert("query_name".to_string(), item.query_name.clone());
    attributes.insert("record_type".to_string(), item.record_type.to_string());
    attributes.insert("response_ips".to_string(), response_ips);

    build_event(
        EventKind::DnsQuery,
        item.timestamp_ms,
        vec![item.query_name.clone()],
        format!(
            "DNS query for {} (type {})",
            item.query_name, item.record_type
        ),
        attributes,
        item,
    )
}

fn tls_handshake_event(item: &TlsHandshakeCapture) -> TypedEvent {
    let mut attributes = BTreeMap::new();
    attributes.insert("sni".to_string(), item.sni.clone());
    attributes.insert("cipher_suite".to_string(), item.cipher_suite.clone());
    attributes.insert(
        "cert_chain_fingerprints".to_string(),
        item.cert_chain_fingerprints.join(","),
    );
    // JA3 client fingerprint + ALPN, populated by the live CONNECT capture in
    // omnisec-mitm::tls. Empty for legacy captures that predate that path.
    attributes.insert("ja3".to_string(), item.ja3.clone());
    attributes.insert("ja3_hash".to_string(), item.ja3_hash.clone());
    attributes.insert("alpn".to_string(), item.alpn.join(","));

    build_event(
        EventKind::TlsHandshake,
        item.timestamp_ms,
        vec![item.sni.clone()],
        format!(
            "TLS handshake with SNI {} using {} (JA3 {})",
            item.sni, item.cipher_suite, item.ja3_hash
        ),
        attributes,
        item,
    )
}

fn flow_summary_event(item: &FlowSummaryCapture) -> TypedEvent {
    let src = format!("{}:{}", item.src_ip, item.src_port);
    let dst = format!("{}:{}", item.dst_ip, item.dst_port);

    let mut attributes = BTreeMap::new();
    attributes.insert("src".to_string(), src.clone());
    attributes.insert("dst".to_string(), dst.clone());
    attributes.insert("bytes".to_string(), item.bytes.to_string());
    attributes.insert("duration_ms".to_string(), item.duration_ms.to_string());
    attributes.insert("protocol".to_string(), item.protocol.clone());

    build_event(
        EventKind::FlowSummary,
        item.timestamp_ms,
        vec![format!("{src} -> {dst}")],
        format!(
            "{} flow {src} -> {dst} ({} bytes, {} ms)",
            item.protocol, item.bytes, item.duration_ms
        ),
        attributes,
        item,
    )
}

fn headers_json(headers: &BTreeMap<String, String>) -> String {
    omnisec_json::to_json_string(headers)
}

fn build_event<T: omnisec_json::ToJson>(
    kind: EventKind,
    observed_at_ms: u64,
    subjects: Vec<String>,
    description: String,
    attributes: BTreeMap<String, String>,
    item: &T,
) -> TypedEvent {
    let item_json = omnisec_json::to_json_vec(item);
    TypedEvent {
        id: event_id(kind, &item_json),
        sensor_id: SENSOR_ID.to_string(),
        kind,
        observed_at_ms,
        subjects,
        description,
        score: 1.0,
        attributes,
        evidence_refs: Vec::new(),
    }
}

/// Content-addressed event id: `sha256(sensor_id || kind-json || item-json)`,
/// hex-encoded. Deterministic for the same input, so re-converting the same
/// capture data always yields the same id.
fn event_id(kind: EventKind, item_json: &[u8]) -> String {
    let kind_json = omnisec_json::to_json_vec(&kind);

    let mut hasher = Sha256::new();
    hasher.update(SENSOR_ID.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(&kind_json);
    hasher.update(&[0u8]);
    hasher.update(item_json);
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_capture() -> MitmCapture {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "example.com".to_string());

        MitmCapture {
            http_requests: vec![HttpRequestCapture {
                timestamp_ms: 1,
                method: "GET".to_string(),
                url: "/index.html".to_string(),
                headers: headers.clone(),
            }],
            http_responses: vec![HttpResponseCapture {
                timestamp_ms: 2,
                status: 200,
                headers,
                request_method: Some("GET".to_string()),
                request_url: Some("/index.html".to_string()),
            }],
            dns_queries: vec![DnsQueryCapture {
                timestamp_ms: 3,
                query_name: "example.com".to_string(),
                record_type: 1,
                response_ips: vec![Ipv4Addr::new(93, 184, 216, 34)],
            }],
            tls_handshakes: vec![TlsHandshakeCapture {
                timestamp_ms: 4,
                sni: "example.com".to_string(),
                cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
                cert_chain_fingerprints: vec!["deadbeef".to_string()],
                ja3: "771,4865,0-16,,".to_string(),
                ja3_hash: "abc123".to_string(),
                alpn: vec!["h2".to_string()],
            }],
            flow_summaries: vec![FlowSummaryCapture {
                timestamp_ms: 5,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                src_port: 51234,
                dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                dst_port: 443,
                bytes: 4096,
                duration_ms: 250,
                protocol: "tcp".to_string(),
            }],
        }
    }

    #[test]
    fn from_mitm_capture_produces_one_event_per_item() {
        let capture = sample_capture();
        let events = from_mitm_capture(&capture);

        assert_eq!(events.len(), 5);
        for event in &events {
            assert_eq!(event.sensor_id, SENSOR_ID);
            assert!(!event.id.is_empty());
        }

        assert_eq!(events[0].kind, EventKind::HttpRequest);
        assert_eq!(events[0].observed_at_ms, 1);
        assert_eq!(events[1].kind, EventKind::HttpResponse);
        assert_eq!(events[1].observed_at_ms, 2);
        assert_eq!(
            events[1].attributes.get("method").map(String::as_str),
            Some("GET")
        );
        assert_eq!(
            events[1].attributes.get("url").map(String::as_str),
            Some("/index.html")
        );
        assert_eq!(events[2].kind, EventKind::DnsQuery);
        assert_eq!(events[2].observed_at_ms, 3);
        assert_eq!(events[3].kind, EventKind::TlsHandshake);
        assert_eq!(events[3].observed_at_ms, 4);
        assert_eq!(events[4].kind, EventKind::FlowSummary);
        assert_eq!(events[4].observed_at_ms, 5);
    }

    #[test]
    fn from_mitm_capture_is_id_stable_across_conversions() {
        let capture = sample_capture();
        let first = from_mitm_capture(&capture);
        let second = from_mitm_capture(&capture);

        let first_ids: Vec<&str> = first.iter().map(|e| e.id.as_str()).collect();
        let second_ids: Vec<&str> = second.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(first_ids, second_ids);
    }

    #[test]
    fn distinct_items_of_the_same_kind_produce_distinct_ids() {
        let mut capture = MitmCapture::default();
        capture.http_requests.push(HttpRequestCapture {
            timestamp_ms: 1,
            method: "GET".to_string(),
            url: "/a".to_string(),
            headers: BTreeMap::new(),
        });
        capture.http_requests.push(HttpRequestCapture {
            timestamp_ms: 1,
            method: "GET".to_string(),
            url: "/b".to_string(),
            headers: BTreeMap::new(),
        });

        let events = from_mitm_capture(&capture);
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].id, events[1].id);
    }

    #[test]
    fn empty_capture_produces_no_events() {
        let events = from_mitm_capture(&MitmCapture::default());
        assert!(events.is_empty());
    }
}
