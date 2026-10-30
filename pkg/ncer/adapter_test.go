package ncer

import (
	"encoding/json"
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func newTestStore(t *testing.T) *EvidenceStore {
	t.Helper()
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}
	return store
}

func TestFromCorrelations_MapsFields(t *testing.T) {
	correlations := []types.Correlation{
		{
			Type:        types.CorrelationCallChain,
			Category:    types.CategoryLicenseCheck,
			Files:       []string{"com/example/Foo.java", "com/example/Bar.java"},
			Description: "shared license check chain",
			Score:       0.82,
		},
	}

	events, err := FromCorrelations(correlations, 1_752_400_000_000, newTestStore(t))
	if err != nil {
		t.Fatalf("FromCorrelations: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.SensorID != sensorIDCorrelationEngine {
		t.Errorf("SensorID = %q, want %q", e.SensorID, sensorIDCorrelationEngine)
	}
	if e.Kind != EventKindCorrelation {
		t.Errorf("Kind = %q, want %q", e.Kind, EventKindCorrelation)
	}
	if e.ObservedAtMs != 1_752_400_000_000 {
		t.Errorf("ObservedAtMs = %d, want 1752400000000", e.ObservedAtMs)
	}
	if e.Description != correlations[0].Description {
		t.Errorf("Description = %q, want %q", e.Description, correlations[0].Description)
	}
	if e.Score != correlations[0].Score {
		t.Errorf("Score = %v, want %v", e.Score, correlations[0].Score)
	}
	if len(e.Subjects) != 2 || e.Subjects[0] != "com/example/Foo.java" {
		t.Errorf("Subjects = %v, want the correlation's Files", e.Subjects)
	}
	if got := e.Attributes["correlation_type"]; got != "call_chain" {
		t.Errorf(`Attributes["correlation_type"] = %q, want "call_chain"`, got)
	}
	if got := e.Attributes["category"]; got != string(types.CategoryLicenseCheck) {
		t.Errorf("Attributes[category] = %q, want %q", got, types.CategoryLicenseCheck)
	}
	if e.ID == "" {
		t.Error("ID must not be empty")
	}
	if len(e.EvidenceRefs) != 1 || e.EvidenceRefs[0] == "" {
		t.Errorf("EvidenceRefs = %v, want a single non-empty hash", e.EvidenceRefs)
	}
}

func TestFromCorrelations_Empty(t *testing.T) {
	events, err := FromCorrelations(nil, 0, newTestStore(t))
	if err != nil {
		t.Fatalf("FromCorrelations: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestFromCorrelations_IDIsStableAndDistinct(t *testing.T) {
	a := types.Correlation{Type: types.CorrelationCallChain, Files: []string{"a"}, Description: "d1"}
	b := types.Correlation{Type: types.CorrelationCallChain, Files: []string{"a"}, Description: "d1"}
	c := types.Correlation{Type: types.CorrelationCallChain, Files: []string{"b"}, Description: "d2"}

	events, err := FromCorrelations([]types.Correlation{a, b, c}, 0, newTestStore(t))
	if err != nil {
		t.Fatalf("FromCorrelations: %v", err)
	}

	if events[0].ID != events[1].ID {
		t.Errorf("identical correlations produced different ids: %q vs %q", events[0].ID, events[1].ID)
	}
	if events[0].ID == events[2].ID {
		t.Errorf("distinct correlations produced the same id: %q", events[0].ID)
	}
}

// TestFromCorrelations_EvidenceRoundTrips checks that the payload referenced
// by EvidenceRefs is actually retrievable from the store and decodes back
// into the original correlation.
func TestFromCorrelations_EvidenceRoundTrips(t *testing.T) {
	store := newTestStore(t)
	correlation := types.Correlation{
		Type:        types.CorrelationDataFlow,
		Category:    types.CategoryTrialCheck,
		Files:       []string{"a", "b"},
		Description: "evidence round trip",
		Score:       0.33,
	}

	events, err := FromCorrelations([]types.Correlation{correlation}, 0, store)
	if err != nil {
		t.Fatalf("FromCorrelations: %v", err)
	}

	raw, err := store.Retrieve(events[0].EvidenceRefs[0])
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if raw == nil {
		t.Fatal("Retrieve returned nil, expected stored payload")
	}

	var decoded types.Correlation
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal stored payload: %v", err)
	}
	if !reflect.DeepEqual(decoded, correlation) {
		t.Errorf("stored payload = %+v, want %+v", decoded, correlation)
	}
}

// TestFromCorrelations_JSONMatchesRustSchema locks the emitted JSON field
// names to what rust/crates/omnisec-ncer-types expects. If this test needs
// to change, the Rust TypedEvent struct must change to match.
func TestFromCorrelations_JSONMatchesRustSchema(t *testing.T) {
	events, err := FromCorrelations([]types.Correlation{{
		Type:        types.CorrelationSamePackage,
		Category:    types.CategoryPremiumCheck,
		Files:       []string{"f"},
		Description: "d",
		Score:       0.5,
	}}, 42, newTestStore(t))
	if err != nil {
		t.Fatalf("FromCorrelations: %v", err)
	}

	raw, err := json.Marshal(events[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{
		"id", "sensor_id", "kind", "observed_at_ms",
		"subjects", "description", "score", "attributes", "evidence_refs",
	} {
		if _, ok := obj[key]; !ok {
			t.Errorf("missing expected JSON field %q", key)
		}
	}
}
