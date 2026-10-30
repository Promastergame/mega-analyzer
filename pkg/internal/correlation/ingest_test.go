package correlation

import (
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
)

func TestIngestSandbox_MemoryFindingsBecomeSignals(t *testing.T) {
	rep := &sandbox.Report{
		StartedAt: time.Now(),
		Processes: []sandbox.ObservedProcess{{PID: 1, Name: "app"}},
		MemoryAnalysis: &sandbox.MemoryAnalysis{
			Findings: []sandbox.MemoryFinding{
				{
					Type:        "process_injection_sequence",
					Description: "inj",
					ProcessID:   1,
					Severity:    9,
					Confidence:  0.9,
					Evidence:    []string{"VirtualAllocEx"},
				},
				{
					Type:        "executable_memory",
					Description: "rwx",
					ProcessID:   1,
					Severity:    7,
					Confidence:  0.7,
				},
			},
		},
	}
	signals := IngestSandbox(rep)
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(signals))
	}
	typeSeen := map[string]bool{}
	for _, s := range signals {
		typeSeen[s.Type] = true
		if s.ProcessName != "app" {
			t.Fatalf("expected ProcessName=app, got %q", s.ProcessName)
		}
	}
	if !typeSeen[TypeProcessInjection] {
		t.Fatal("expected process_injection type")
	}
	if !typeSeen[TypeRWXMemory] {
		t.Fatal("expected rwx_memory type")
	}
}

func TestIngestSandbox_PublicEgressTaggedReachable(t *testing.T) {
	rep := &sandbox.Report{
		StartedAt: time.Now(),
		Connections: []sandbox.ObservedConnection{
			{
				Protocol:   "TCP",
				LocalAddr:  "10.0.0.2:49152",
				RemoteAddr: "203.0.113.10:443",
				PID:        1,
				FirstSeen:  time.Now(),
			},
		},
	}
	signals := IngestSandbox(rep)
	if len(signals) == 0 {
		t.Fatal("expected at least one signal")
	}
	s := signals[0]
	if s.Type != TypePublicEgress {
		t.Fatalf("expected public_egress, got %s", s.Type)
	}
	if !s.HasTag(TagReachable) {
		t.Fatal("public egress should be tagged reachable")
	}
}

func TestIngestStatic_MapsCleartextEndpoint(t *testing.T) {
	// Build a minimal AnalysisResult with one cleartext-endpoint
	// match.
	res := types.NewAnalysisResult("/tmp")
	fa := types.NewFileAnalysis("f.smali", types.FileTypeSmali, 123)
	fa.Matches = append(fa.Matches, types.Match{
		Categorized:    types.Categorized{Category: types.CategoryVulnerability},
		SourceLocation: types.SourceLocation{File: "f.smali", Line: 10},
		Pattern:        "cleartext HTTP endpoint: http://example.com",
		Text:           "http://example.com",
		Severity:       types.SeverityHigh,
	})
	res.AddFile("f.smali", fa)

	signals := IngestStatic(res)
	if len(signals) == 0 {
		t.Fatal("expected at least one static signal")
	}
	var cleartext *Signal
	for _, s := range signals {
		if s.Type == TypeCleartextEndpoint {
			cleartext = s
		}
	}
	if cleartext == nil {
		t.Fatal("expected a TypeCleartextEndpoint signal")
	}
	if !cleartext.HasTag(TagReachable) {
		t.Fatal("cleartext endpoint should be tagged reachable")
	}
	if cleartext.Kind != KindAudit {
		t.Fatalf("expected KindAudit, got %s", cleartext.Kind)
	}
	if cleartext.Location.File != "f.smali" || cleartext.Location.Line != 10 {
		t.Fatalf("expected location preserved, got %+v", cleartext.Location)
	}
}

func TestIngestStatic_MapsHardcodedSecret(t *testing.T) {
	res := types.NewAnalysisResult("/tmp")
	fa := types.NewFileAnalysis("f.smali", types.FileTypeSmali, 123)
	fa.Matches = append(fa.Matches, types.Match{
		Categorized:    types.Categorized{Category: types.CategoryCredential},
		SourceLocation: types.SourceLocation{File: "f.smali"},
		Pattern:        "hardcoded Bearer token",
		Severity:       types.SeverityCritical,
		IsCritical:     true,
	})
	res.AddFile("f.smali", fa)

	signals := IngestStatic(res)
	if len(signals) == 0 || signals[0].Type != TypeHardcodedSecret {
		t.Fatalf("expected hardcoded_secret signal, got %+v", signals)
	}
	if signals[0].Severity < 7 {
		t.Fatalf("critical match should have severity >= 7, got %d", signals[0].Severity)
	}
}

// Regression (subwaysurf): native .so string blobs matching entitlement
// substrings ("isPro" inside libunity.so engine strings) must not become
// client_side_auth_gate signals.
func TestIngestStatic_SkipsNativeLibAuthGates(t *testing.T) {
	res := types.NewAnalysisResult("/tmp")
	fa := types.NewFileAnalysis("lib/arm64-v8a/libunity.so", types.FileTypeNative, 1<<20)
	fa.Matches = append(fa.Matches, types.Match{
		Categorized:    types.Categorized{Category: types.CategoryPremiumCheck},
		SourceLocation: types.SourceLocation{File: `lib\arm64-v8a\libunity.so`, Line: 1040},
		Pattern:        "Pro status check",
		Text:           "playOnAwake isPro gradient",
		Severity:       types.SeverityHigh,
		IsCritical:     true,
	})
	res.AddFile("libunity.so", fa)

	for _, s := range IngestStatic(res) {
		if s.Type == TypeAuthGate {
			t.Fatalf("native .so blob must not emit auth gate, got %+v", s)
		}
	}
}

// Regression (subwaysurf): Android accessibility probes
// (hasAccessibilityDisplayDaltonizer) must not become auth gates even if a
// detector emits them under a premium category.
func TestIngestStatic_SkipsAccessibilityAuthGates(t *testing.T) {
	res := types.NewAnalysisResult("/tmp")
	fa := types.NewFileAnalysis("a.smali", types.FileTypeSmali, 123)
	fa.Matches = append(fa.Matches, types.Match{
		Categorized:    types.Categorized{Category: types.CategoryPremiumCheck},
		SourceLocation: types.SourceLocation{File: "a.smali", Line: 98},
		Pattern:        "Access check",
		Text:           ".method public abstract hasAccessibilityDisplayDaltonizer()Z",
		Severity:       types.SeverityLow,
	})
	res.AddFile("a.smali", fa)

	for _, s := range IngestStatic(res) {
		if s.Type == TypeAuthGate {
			t.Fatalf("accessibility probe must not emit auth gate, got %+v", s)
		}
	}
}

// Sanity: a real smali premium gate still maps to TypeAuthGate.
func TestIngestStatic_KeepsSmaliAuthGate(t *testing.T) {
	res := types.NewAnalysisResult("/tmp")
	fa := types.NewFileAnalysis("b.smali", types.FileTypeSmali, 123)
	fa.Matches = append(fa.Matches, types.Match{
		Categorized:    types.Categorized{Category: types.CategoryPremiumCheck},
		SourceLocation: types.SourceLocation{File: "b.smali", Line: 10},
		Pattern:        "Has premium check",
		Text:           "invoke-virtual {p0}, Lcom/app/Billing;->hasPremium()Z",
		Severity:       types.SeverityHigh,
		IsCritical:     true,
	})
	res.AddFile("b.smali", fa)

	found := false
	for _, s := range IngestStatic(res) {
		if s.Type == TypeAuthGate {
			found = true
		}
	}
	if !found {
		t.Fatal("real smali premium gate must still emit auth gate signal")
	}
}
