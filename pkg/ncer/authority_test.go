package ncer

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

func sampleAuthorityContext() AuthorityContext {
	return AuthorityContext{
		Subject: Subject{
			ID:   "com.example.app",
			Kind: "app",
			Name: "Example App",
		},
		Identity: Identity{
			Principal:       "uid:10150",
			CredentialsHash: "abc123hash",
			Issuer:          "android",
		},
		Granted: []GrantedPermission{
			{
				Name:   "android.permission.INTERNET",
				Scope:  "normal",
				Source: "AndroidManifest.xml",
			},
		},
		Observed: []ObservedAction{
			{
				Action:      "network_connect",
				Target:      "api.example.com",
				TimestampMs: 1700000000000,
			},
		},
	}
}

func TestAuthorityContext_JSONRoundTrip(t *testing.T) {
	ctx := sampleAuthorityContext()
	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded AuthorityContext
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(decoded, ctx) {
		t.Errorf("round trip mismatch:\ngot  %+v\nwant %+v", decoded, ctx)
	}
}

func TestFromAuthorityContext_NilStore(t *testing.T) {
	ctx := sampleAuthorityContext()
	evt, err := FromAuthorityContext(ctx, "sensor.manifest", 1000, nil)
	if err != nil {
		t.Fatalf("FromAuthorityContext failed: %v", err)
	}

	if evt.Kind != EventKindAuthorityGrant {
		t.Errorf("unexpected kind: %s", evt.Kind)
	}
	if len(evt.EvidenceRefs) != 0 {
		t.Errorf("expected empty evidence refs when store is nil")
	}
	if evt.Attributes["subject_id"] != "com.example.app" {
		t.Errorf("missing attribute subject_id")
	}
}

func TestFromAuthorityContext_WithEvidenceStore(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := OpenEvidenceStore(filepath.Join(tmpDir, "evidence"))
	if err != nil {
		t.Fatalf("OpenEvidenceStore failed: %v", err)
	}

	ctx := sampleAuthorityContext()
	evt, err := FromAuthorityContext(ctx, "sensor.manifest", 1000, store)
	if err != nil {
		t.Fatalf("FromAuthorityContext failed: %v", err)
	}

	if len(evt.EvidenceRefs) != 1 {
		t.Fatalf("expected 1 evidence reference, got %d", len(evt.EvidenceRefs))
	}

	// Verify the stored evidence matches our context payload
	hash := evt.EvidenceRefs[0]
	verified, err := store.Verify(hash)
	if err != nil || !verified {
		t.Fatalf("evidence verification failed: verified=%v err=%v", verified, err)
	}

	data, err := store.Retrieve(hash)
	if err != nil || data == nil {
		t.Fatalf("retrieve evidence failed: err=%v", err)
	}

	var storedCtx AuthorityContext
	if err := json.Unmarshal(data, &storedCtx); err != nil {
		t.Fatalf("unmarshal stored context: %v", err)
	}
	if !reflect.DeepEqual(storedCtx, ctx) {
		t.Errorf("stored context mismatch: %+v vs %+v", storedCtx, ctx)
	}
}

func TestFromAuthorityContextGranular_OneEventPerGrantAndObservedAction(t *testing.T) {
	ctx := sampleAuthorityContext()
	events := FromAuthorityContextGranular(ctx, "sensor.manifest", 1000)

	if len(events) != len(ctx.Granted)+len(ctx.Observed) {
		t.Fatalf("expected %d events, got %d", len(ctx.Granted)+len(ctx.Observed), len(events))
	}

	grant := events[0]
	if grant.Kind != EventKindAuthorityGrant {
		t.Errorf("events[0].Kind = %s, want %s", grant.Kind, EventKindAuthorityGrant)
	}
	if grant.Attributes["subject_id"] != "com.example.app" {
		t.Errorf("grant subject_id = %q", grant.Attributes["subject_id"])
	}
	if grant.Attributes["permission"] != "android.permission.INTERNET" {
		t.Errorf("grant permission = %q", grant.Attributes["permission"])
	}

	observed := events[1]
	if observed.Kind != EventKindAuthorityObserved {
		t.Errorf("events[1].Kind = %s, want %s", observed.Kind, EventKindAuthorityObserved)
	}
	if observed.Attributes["required_permission"] != "android.permission.INTERNET" {
		t.Errorf("observed required_permission = %q, want android.permission.INTERNET",
			observed.Attributes["required_permission"])
	}
	if observed.ObservedAtMs != ctx.Observed[0].TimestampMs {
		t.Errorf("observed.ObservedAtMs = %d, want %d", observed.ObservedAtMs, ctx.Observed[0].TimestampMs)
	}
}

func TestFromAuthorityContextGranular_UnmappedActionHasEmptyRequiredPermission(t *testing.T) {
	ctx := sampleAuthorityContext()
	ctx.Observed = []ObservedAction{{Action: "some_unmapped_action", Target: "x", TimestampMs: 1}}

	events := FromAuthorityContextGranular(ctx, "sensor.manifest", 1000)
	observed := events[len(events)-1]
	if observed.Attributes["required_permission"] != "" {
		t.Errorf("unmapped action should have empty required_permission, got %q",
			observed.Attributes["required_permission"])
	}
}

func TestFromAuthorityContextGranular_IDsAreDistinct(t *testing.T) {
	ctx := sampleAuthorityContext()
	ctx.Observed = append(ctx.Observed, ObservedAction{
		Action: "network_connect", Target: "other.example.com", TimestampMs: 2,
	})

	events := FromAuthorityContextGranular(ctx, "sensor.manifest", 1000)
	seen := map[string]bool{}
	for _, e := range events {
		if seen[e.ID] {
			t.Errorf("duplicate event id: %s", e.ID)
		}
		seen[e.ID] = true
	}
}

func TestFromAuthorityContextGranular_EmptyContextProducesNoEvents(t *testing.T) {
	ctx := AuthorityContext{Subject: Subject{ID: "com.example.app"}}
	events := FromAuthorityContextGranular(ctx, "sensor.manifest", 1000)
	if len(events) != 0 {
		t.Errorf("expected 0 events for empty context, got %d", len(events))
	}
}

func TestActionToPermission_KnownAndUnknown(t *testing.T) {
	perm, ok := ActionToPermission("network_connect")
	if !ok || perm != "android.permission.INTERNET" {
		t.Errorf("ActionToPermission(network_connect) = (%q, %v)", perm, ok)
	}

	_, ok = ActionToPermission("totally_unknown_action")
	if ok {
		t.Errorf("expected no mapping for an unknown action")
	}
}

func TestAuthorityMappingCoverage_EmptyIsFullyCovered(t *testing.T) {
	mapped, total, frac := AuthorityMappingCoverage(nil)
	if mapped != 0 || total != 0 || frac != 1.0 {
		t.Errorf("empty coverage = (%d, %d, %v), want (0, 0, 1.0)", mapped, total, frac)
	}
}

func TestAuthorityMappingCoverage_MixedActions(t *testing.T) {
	actions := []string{
		"network_connect",      // mapped
		"dns_query",            // mapped
		"some_unmapped_action", // unmapped
		"another_unknown",      // unmapped
	}
	mapped, total, frac := AuthorityMappingCoverage(actions)
	if mapped != 2 || total != 4 {
		t.Errorf("coverage counts = (%d, %d), want (2, 4)", mapped, total)
	}
	if abs64(frac-0.5) > 1e-9 {
		t.Errorf("coverage fraction = %v, want 0.5", frac)
	}
}

func TestAuthorityMappingCoverage_AllMapped(t *testing.T) {
	actions := []string{"network_connect", "sms_send", "location_fine", "camera_access"}
	mapped, total, frac := AuthorityMappingCoverage(actions)
	if mapped != total || frac != 1.0 {
		t.Errorf("all-mapped coverage = (%d/%d, %v), want full", mapped, total, frac)
	}
}

func abs64(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
