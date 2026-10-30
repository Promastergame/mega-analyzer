//! Shared typed-event schema for the NCER (Network Claim-Evidence
//! Reconciliation) layer.
//!
//! This crate defines only the wire-level data structures that every NCER
//! sensor/adapter normalizes its output into. It intentionally contains no
//! reconciliation, scoring, or policy logic — that belongs to later phases
//! (`omnisec-ncer-reconcile`, `omnisec-ncer-compliance`, ...) once they
//! exist. The Go-side mirror of this schema lives in `pkg/ncer` and must be
//! kept in sync field-for-field, since events cross the Go/Rust boundary as
//! JSON.

use std::collections::BTreeMap;

use omnisec_json::{FromJson, ToJson};

/// What kind of signal a [`TypedEvent`] carries.
///
/// `Correlation` is fed by Mega-Analyzer's existing static correlation
/// engine. `HttpRequest`, `HttpResponse`, `DnsQuery`, `TlsHandshake`, and
/// `FlowSummary` are fed by `omnisec-ncer-parse-net`, which converts
/// `omnisec-mitm` capture data. Future sensors add variants here as they're
/// wired in — this enum is expected to grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum EventKind {
    /// Derived from `pkg/internal/analyzer.CorrelationFinder` output.
    Correlation,
    /// A captured outbound HTTP request (`omnisec-mitm::capture::HttpRequestCapture`).
    HttpRequest,
    /// A captured HTTP response (`omnisec-mitm::capture::HttpResponseCapture`).
    HttpResponse,
    /// A captured DNS query and answer (`omnisec-mitm::capture::DnsQueryCapture`).
    DnsQuery,
    /// A captured TLS handshake (`omnisec-mitm::capture::TlsHandshakeCapture`).
    TlsHandshake,
    /// A captured network flow summary (`omnisec-mitm::capture::FlowSummaryCapture`).
    FlowSummary,
    /// A declared or granted authority permission claim.
    AuthorityGrant,
    /// An observed action exercising sensitive authority.
    AuthorityObserved,
    /// A reconstructed application session over a single flow, produced by
    /// `omnisec-capture`'s reassembler (5-tuple, protocol, reassembled streams).
    SessionSummary,
    /// A single WebSocket frame decoded from an upgraded HTTP connection.
    WebSocketMessage,
    /// One decoded HTTP/2 stream (HEADERS+DATA reassembled by stream id).
    Http2Stream,
    /// A DNS answer split out from its query so resolutions can be bound as
    /// first-class effects (closes the `effect_binder` DNS TODO).
    DnsAnswer,
    /// A raw TCP segment observation, for causal reassembly and gap analysis.
    TcpSegment,
    /// A QUIC transport event (Initial packet / connection observation).
    QuicEvent,
}

/// Identifies an acting entity under scrutiny (e.g., application package or service).
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct Subject {
    /// Stable identifier for the subject (e.g. an Android package name).
    pub id: String,
    /// Category of subject (e.g. `"app"`, `"service"`).
    pub kind: String,
    /// Human-readable display name.
    pub name: String,
}

/// Identifies the credentials or principal claiming authority.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct Identity {
    /// The claimed principal (e.g. `"uid:10150"`).
    pub principal: String,
    /// Hash of the credentials backing this identity, never the raw secret.
    pub credentials_hash: String,
    /// Who issued/attested this identity (e.g. `"android"`).
    pub issuer: String,
}

/// Represents a declared or granted permission (e.g., Android manifest permission).
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct GrantedPermission {
    /// Permission identifier (e.g. `"android.permission.INTERNET"`).
    pub name: String,
    /// Scope the permission was granted under (e.g. `"normal"`, `"dangerous"`).
    pub scope: String,
    /// Where the grant was declared (e.g. `"AndroidManifest.xml"`).
    pub source: String,
}

/// Represents an observed sensitive operation or API usage.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct ObservedAction {
    /// The action performed (e.g. `"network_connect"`).
    pub action: String,
    /// What the action targeted (e.g. a host or file path).
    pub target: String,
    /// Unix epoch milliseconds when the action was observed.
    pub timestamp_ms: u64,
}

/// Container associating a subject and its identity with declared grants and observed actions.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct AuthorityContext {
    /// The entity this context concerns.
    pub subject: Subject,
    /// The credentials/principal claiming authority over `subject`.
    pub identity: Identity,
    /// Permissions declared or granted to `subject`.
    pub granted: Vec<GrantedPermission>,
    /// Sensitive actions observed being performed by `subject`.
    pub observed: Vec<ObservedAction>,
}

impl AuthorityContext {
    /// Normalizes this authority context into a common [`TypedEvent`] envelope.
    pub fn to_typed_event(&self, sensor_id: impl Into<String>, observed_at_ms: u64) -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("subject_id".to_string(), self.subject.id.clone());
        attributes.insert("subject_kind".to_string(), self.subject.kind.clone());
        attributes.insert("principal".to_string(), self.identity.principal.clone());
        attributes.insert("granted_count".to_string(), self.granted.len().to_string());
        attributes.insert(
            "observed_count".to_string(),
            self.observed.len().to_string(),
        );

        TypedEvent {
            id: format!("authority:{}", self.subject.id),
            sensor_id: sensor_id.into(),
            kind: EventKind::AuthorityGrant,
            observed_at_ms,
            subjects: vec![self.subject.id.clone()],
            description: format!(
                "Authority context for {} with {} grants and {} observed actions",
                self.subject.name,
                self.granted.len(),
                self.observed.len()
            ),
            score: 0.0,
            attributes,
            evidence_refs: vec![],
        }
    }
}

/// A single reconcilable unit of evidence entering the NCER pipeline.
///
/// `TypedEvent` is the common envelope every sensor normalizes into before
/// anything downstream (reconcilers, graph, compliance gate) can reason
/// about it. It carries just enough structure to be useful today
/// (id, provenance, subjects, a score) without committing to fields that
/// only later reconciliation phases would need.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct TypedEvent {
    /// Stable identifier for this event, derived from its content so the
    /// same underlying observation always produces the same id.
    pub id: String,
    /// Identifier of the sensor/adapter that produced this event, e.g.
    /// `"analyzer.correlation"`.
    pub sensor_id: String,
    /// What kind of signal this event carries.
    pub kind: EventKind,
    /// Unix epoch milliseconds when the event was observed or derived.
    pub observed_at_ms: u64,
    /// Entities this event concerns (file paths, hosts, packages, ...).
    pub subjects: Vec<String>,
    /// Human-readable description of the observed condition.
    pub description: String,
    /// Confidence/severity score, in the same range as the source finding
    /// it was derived from (today: `[0, 1]` from the correlation engine).
    pub score: f64,
    /// Opaque, kind-specific attributes (e.g. correlation type, category).
    /// A `BTreeMap` keeps serialized output key-ordered and diff-stable.
    pub attributes: BTreeMap<String, String>,
    /// Content-addressable references to raw evidence backing this event.
    /// Empty until an evidence store exists to populate it.
    pub evidence_refs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> TypedEvent {
        let mut attributes = BTreeMap::new();
        attributes.insert("correlation_type".to_string(), "call_chain".to_string());
        attributes.insert("category".to_string(), "License".to_string());

        TypedEvent {
            id: "deadbeef".to_string(),
            sensor_id: "analyzer.correlation".to_string(),
            kind: EventKind::Correlation,
            observed_at_ms: 1_752_400_000_000,
            subjects: vec!["com/example/Foo.java".to_string()],
            description: "test correlation".to_string(),
            score: 0.75,
            attributes,
            evidence_refs: vec![],
        }
    }

    #[test]
    fn event_kind_serializes_as_snake_case() {
        let json = omnisec_json::to_json_string(&EventKind::Correlation);
        assert_eq!(json, "\"correlation\"");
    }

    #[test]
    fn new_event_kind_variants_serialize_as_snake_case() {
        let cases = [
            (EventKind::HttpRequest, "\"http_request\""),
            (EventKind::HttpResponse, "\"http_response\""),
            (EventKind::DnsQuery, "\"dns_query\""),
            (EventKind::TlsHandshake, "\"tls_handshake\""),
            (EventKind::FlowSummary, "\"flow_summary\""),
            (EventKind::AuthorityGrant, "\"authority_grant\""),
            (EventKind::AuthorityObserved, "\"authority_observed\""),
            (EventKind::SessionSummary, "\"session_summary\""),
            (EventKind::WebSocketMessage, "\"web_socket_message\""),
            (EventKind::Http2Stream, "\"http2_stream\""),
            (EventKind::DnsAnswer, "\"dns_answer\""),
            (EventKind::TcpSegment, "\"tcp_segment\""),
            (EventKind::QuicEvent, "\"quic_event\""),
        ];
        for (kind, expected) in cases {
            let json = omnisec_json::to_json_string(&kind);
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn authority_context_round_trips_through_json() {
        let ctx = AuthorityContext {
            subject: Subject {
                id: "com.example.app".to_string(),
                kind: "app".to_string(),
                name: "Example App".to_string(),
            },
            identity: Identity {
                principal: "uid:10150".to_string(),
                credentials_hash: "abc123".to_string(),
                issuer: "android".to_string(),
            },
            granted: vec![GrantedPermission {
                name: "android.permission.INTERNET".to_string(),
                scope: "normal".to_string(),
                source: "AndroidManifest.xml".to_string(),
            }],
            observed: vec![ObservedAction {
                action: "network_connect".to_string(),
                target: "api.example.com".to_string(),
                timestamp_ms: 1000,
            }],
        };

        let json = omnisec_json::to_json_string(&ctx);
        let decoded: AuthorityContext = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, ctx);

        let evt = ctx.to_typed_event("sensor.manifest", 1000);
        assert_eq!(evt.kind, EventKind::AuthorityGrant);
        assert_eq!(evt.subjects, vec!["com.example.app"]);
    }

    #[test]
    fn typed_event_round_trips_through_json() {
        let event = sample_event();
        let json = omnisec_json::to_json_string(&event);
        let decoded: TypedEvent = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn typed_event_json_uses_expected_field_names() {
        let json = omnisec_json::to_json_value(&sample_event());
        let obj = json.as_object().unwrap();
        let expected = [
            "id",
            "sensor_id",
            "kind",
            "observed_at_ms",
            "subjects",
            "description",
            "score",
            "attributes",
            "evidence_refs",
        ];
        for key in expected {
            assert!(
                obj.iter().any(|(k, _)| k == key),
                "missing expected field {key}"
            );
        }
        // Exact count, not just containment: a silently added/removed field
        // would otherwise pass this test while drifting from pkg/ncer's
        // TypedEvent, which has no compile-time link to this schema.
        assert_eq!(
            obj.len(),
            expected.len(),
            "TypedEvent gained or lost a field; update pkg/ncer/adapter.go's \
             TypedEvent to match, then update this test's expected field list"
        );
    }
}
