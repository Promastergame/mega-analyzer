package ncer

import (
	"encoding/json"
	"fmt"
)

// Subject identifies an acting entity under scrutiny (e.g., application package or service).
type Subject struct {
	// ID is a stable identifier for the subject (e.g. an Android package name).
	ID string `json:"id"`
	// Kind is the category of subject (e.g. "app", "service").
	Kind string `json:"kind"`
	// Name is a human-readable display name.
	Name string `json:"name"`
}

// Identity identifies the credentials or principal claiming authority.
type Identity struct {
	// Principal is the claimed principal (e.g. "uid:10150").
	Principal string `json:"principal"`
	// CredentialsHash hashes the credentials backing this identity, never
	// the raw secret.
	CredentialsHash string `json:"credentials_hash"`
	// Issuer is who issued/attested this identity (e.g. "android").
	Issuer string `json:"issuer"`
}

// GrantedPermission represents a declared or granted permission (e.g., Android manifest permission).
type GrantedPermission struct {
	// Name is the permission identifier (e.g. "android.permission.INTERNET").
	Name string `json:"name"`
	// Scope is the scope the permission was granted under (e.g. "normal", "dangerous").
	Scope string `json:"scope"`
	// Source is where the grant was declared (e.g. "AndroidManifest.xml").
	Source string `json:"source"`
}

// ObservedAction represents an observed sensitive operation or API usage.
type ObservedAction struct {
	// Action is the action performed (e.g. "network_connect").
	Action string `json:"action"`
	// Target is what the action targeted (e.g. a host or file path).
	Target string `json:"target"`
	// TimestampMs is the Unix epoch milliseconds when the action was observed.
	TimestampMs int64 `json:"timestamp_ms"`
}

// AuthorityContext associates a subject and its identity with declared grants and observed actions.
type AuthorityContext struct {
	// Subject is the entity this context concerns.
	Subject Subject `json:"subject"`
	// Identity is the credentials/principal claiming authority over Subject.
	Identity Identity `json:"identity"`
	// Granted lists permissions declared or granted to Subject.
	Granted []GrantedPermission `json:"granted"`
	// Observed lists sensitive actions observed being performed by Subject.
	Observed []ObservedAction `json:"observed"`
}

// FromAuthorityContextGranular converts an AuthorityContext into the
// per-event TypedEvents the Rust authority binder needs to compute
// d_authority/d_capability (rust/crates/omnisec-ncer-reconcile/src/
// authority_binder.rs): one EventKindAuthorityGrant event per granted
// permission (keyed on subject_id+permission), and one
// EventKindAuthorityObserved event per observed action. An action whose
// Action string has no entry in ActionToPermission still produces an event
// (so it is still counted in TotalEvents) but with an empty
// required_permission attribute; the Rust authority binder treats that as
// unclassifiable and excludes it from binding entirely — see
// rust/crates/omnisec-ncer-reconcile/src/authority_binder.rs's module doc.
// This is a finer-grained sibling of FromAuthorityContext,
// which emits a single aggregated grant event with no per-action detail;
// callers that want the FFI's d_authority/d_capability scoring should use
// this function's output for the authority_events sent alongside a capture.
//
// Unlike FromAuthorityContext, neither event kind is stored in an
// EvidenceStore here: these events exist purely to cross the FFI boundary
// for scoring, not to be archived as findings in their own right.
func FromAuthorityContextGranular(ctx AuthorityContext, sensorID string, observedAtMs int64) []TypedEvent {
	events := make([]TypedEvent, 0, len(ctx.Granted)+len(ctx.Observed))

	for _, g := range ctx.Granted {
		events = append(events, TypedEvent{
			ID:           fmt.Sprintf("authority-grant:%s:%s", ctx.Subject.ID, g.Name),
			SensorID:     sensorID,
			Kind:         EventKindAuthorityGrant,
			ObservedAtMs: observedAtMs,
			Subjects:     []string{ctx.Subject.ID},
			Description:  fmt.Sprintf("%s granted %s (%s)", ctx.Subject.Name, g.Name, g.Scope),
			Score:        0.0,
			Attributes: map[string]string{
				"subject_id": ctx.Subject.ID,
				"permission": g.Name,
				"scope":      g.Scope,
				"source":     g.Source,
			},
			EvidenceRefs: []string{},
		})
	}

	for i, a := range ctx.Observed {
		perm, _ := ActionToPermission(a.Action)
		events = append(events, TypedEvent{
			ID:           fmt.Sprintf("authority-observed:%s:%d:%s", ctx.Subject.ID, i, a.Action),
			SensorID:     sensorID,
			Kind:         EventKindAuthorityObserved,
			ObservedAtMs: a.TimestampMs,
			Subjects:     []string{ctx.Subject.ID},
			Description:  fmt.Sprintf("%s performed %s on %s", ctx.Subject.Name, a.Action, a.Target),
			Score:        0.0,
			Attributes: map[string]string{
				"subject_id":          ctx.Subject.ID,
				"action":              a.Action,
				"target":              a.Target,
				"required_permission": perm,
			},
			EvidenceRefs: []string{},
		})
	}

	return events
}

// FromAuthorityContext converts an AuthorityContext into an NCER TypedEvent,
// storing the context payload in the EvidenceStore if provided.
func FromAuthorityContext(ctx AuthorityContext, sensorID string, observedAtMs int64, store *EvidenceStore) (TypedEvent, error) {
	var evRefs []string
	if store != nil {
		payload, err := json.Marshal(ctx)
		if err != nil {
			return TypedEvent{}, fmt.Errorf("ncer: marshal authority context payload: %w", err)
		}
		hash, err := store.Store(payload)
		if err != nil {
			return TypedEvent{}, fmt.Errorf("ncer: store authority evidence: %w", err)
		}
		evRefs = []string{hash}
	}

	attrs := map[string]string{
		"subject_id":     ctx.Subject.ID,
		"subject_kind":   ctx.Subject.Kind,
		"principal":      ctx.Identity.Principal,
		"granted_count":  fmt.Sprintf("%d", len(ctx.Granted)),
		"observed_count": fmt.Sprintf("%d", len(ctx.Observed)),
	}

	evt := TypedEvent{
		ID:           fmt.Sprintf("authority:%s", ctx.Subject.ID),
		SensorID:     sensorID,
		Kind:         EventKindAuthorityGrant,
		ObservedAtMs: observedAtMs,
		Subjects:     []string{ctx.Subject.ID},
		Description:  fmt.Sprintf("Authority context for %s with %d grants and %d observed actions", ctx.Subject.Name, len(ctx.Granted), len(ctx.Observed)),
		Score:        0.0,
		Attributes:   attrs,
		EvidenceRefs: evRefs,
	}

	return evt, nil
}
