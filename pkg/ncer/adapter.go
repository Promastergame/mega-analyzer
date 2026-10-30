// Package ncer is the Go-side coordination point for the NCER (Network
// Claim-Evidence Reconciliation) layer: the TypedEvent envelope, an evidence
// store, and an adapter that converts the existing static correlation
// engine's output into typed events backed by stored evidence.
// Reconciliation, receipts, and the compliance gate are later-phase
// concerns and do not live here yet.
package ncer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"mega-analyzer/pkg/internal/types"
)

// EventKind identifies what kind of signal a TypedEvent carries.
//
// This mirrors omnisec-ncer-types::EventKind (rust/crates/omnisec-ncer-types)
// field-for-field; the two must be kept in sync since events cross the
// Go/Rust boundary as JSON.
type EventKind string

const (
	// EventKindCorrelation is emitted from Mega-Analyzer's existing static
	// correlation engine (pkg/internal/analyzer.CorrelationFinder).
	EventKindCorrelation EventKind = "correlation"
	// EventKindAuthorityGrant marks a declared or granted authority
	// permission claim (see FromAuthorityContext).
	EventKindAuthorityGrant EventKind = "authority_grant"
	// EventKindAuthorityObserved marks an observed action exercising
	// sensitive authority.
	EventKindAuthorityObserved EventKind = "authority_observed"
	// EventKindHTTPRequest is a captured outbound HTTP request.
	EventKindHTTPRequest EventKind = "http_request"
	// EventKindHTTPResponse is a captured HTTP response.
	EventKindHTTPResponse EventKind = "http_response"
	// EventKindDNSQuery is a captured DNS query (and, historically, its answer).
	EventKindDNSQuery EventKind = "dns_query"
	// EventKindTLSHandshake is a captured TLS handshake (SNI, JA3, cipher).
	EventKindTLSHandshake EventKind = "tls_handshake"
	// EventKindFlowSummary is a captured network flow summary.
	EventKindFlowSummary EventKind = "flow_summary"
	// EventKindSessionSummary is a reconstructed application session over one
	// flow, produced by the omnisec-capture reassembler.
	EventKindSessionSummary EventKind = "session_summary"
	// EventKindWebSocketMessage is a single decoded WebSocket frame.
	EventKindWebSocketMessage EventKind = "web_socket_message"
	// EventKindHTTP2Stream is one decoded HTTP/2 stream.
	EventKindHTTP2Stream EventKind = "http2_stream"
	// EventKindDNSAnswer is a DNS answer split from its query so resolutions
	// can be bound as first-class effects.
	EventKindDNSAnswer EventKind = "dns_answer"
	// EventKindTCPSegment is a raw TCP segment observation.
	EventKindTCPSegment EventKind = "tcp_segment"
	// EventKindQUICEvent is a QUIC transport event.
	EventKindQUICEvent EventKind = "quic_event"
)

// sensorIDCorrelationEngine identifies the adapter in this file as a sensor.
const sensorIDCorrelationEngine = "analyzer.correlation"

// TypedEvent is the common envelope every NCER sensor/adapter normalizes its
// output into. It mirrors omnisec-ncer-types::TypedEvent; JSON field names
// must match that crate's serde output exactly.
type TypedEvent struct {
	// ID is a stable identifier derived from this event's content, so the
	// same underlying observation always produces the same id.
	ID string `json:"id"`
	// SensorID identifies the sensor/adapter that produced this event, e.g.
	// "analyzer.correlation".
	SensorID string `json:"sensor_id"`
	// Kind is what kind of signal this event carries.
	Kind EventKind `json:"kind"`
	// ObservedAtMs is the Unix epoch milliseconds when the event was
	// observed or derived.
	ObservedAtMs int64 `json:"observed_at_ms"`
	// Subjects are the entities this event concerns (file paths, hosts,
	// packages, ...).
	Subjects []string `json:"subjects"`
	// Description is a human-readable summary of the observed condition.
	Description string `json:"description"`
	// Score is a confidence/severity score in the same range as the source
	// finding it was derived from (today: [0, 1] from the correlation engine).
	Score float64 `json:"score"`
	// Attributes holds opaque, kind-specific attributes (e.g. correlation
	// type, category).
	Attributes map[string]string `json:"attributes"`
	// EvidenceRefs are content-addressable references to raw evidence
	// backing this event.
	EvidenceRefs []string `json:"evidence_refs"`
}

// FromCorrelations converts the static correlation engine's output
// (pkg/internal/analyzer.CorrelationFinder.FindAll) into NCER TypedEvents,
// storing each correlation's original payload in store and recording the
// returned hash as the event's evidence reference.
//
// observedAtMs is taken as a parameter rather than sampled internally so the
// conversion stays a deterministically testable function; callers pass the
// time the underlying analysis run completed.
func FromCorrelations(correlations []types.Correlation, observedAtMs int64, store *EvidenceStore) ([]TypedEvent, error) {
	events := make([]TypedEvent, 0, len(correlations))
	for _, c := range correlations {
		payload, err := json.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("ncer: marshal correlation payload: %w", err)
		}

		evidenceHash, err := store.Store(payload)
		if err != nil {
			return nil, fmt.Errorf("ncer: store correlation evidence: %w", err)
		}

		events = append(events, TypedEvent{
			ID:           correlationEventID(c),
			SensorID:     sensorIDCorrelationEngine,
			Kind:         EventKindCorrelation,
			ObservedAtMs: observedAtMs,
			Subjects:     append([]string(nil), c.Files...),
			Description:  c.Description,
			Score:        c.Score,
			Attributes: map[string]string{
				"correlation_type": c.Type.String(),
				"category":         string(c.Category),
			},
			EvidenceRefs: []string{evidenceHash},
		})
	}
	return events, nil
}

// correlationEventID derives a stable, content-addressed id for a
// correlation so the same underlying finding always maps to the same event
// id across runs.
func correlationEventID(c types.Correlation) string {
	h := sha256.New()
	h.Write([]byte(c.Type.String()))
	h.Write([]byte{0})
	for _, f := range c.Files {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	h.Write([]byte(c.Description))
	return hex.EncodeToString(h.Sum(nil))
}
