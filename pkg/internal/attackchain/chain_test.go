package attackchain

import (
	"testing"
	"time"

	"mega-analyzer/pkg/internal/correlation"
)

func TestProcessInjectionChain_DetectsCanonicalSequence(t *testing.T) {
	t0 := time.Now()
	signals := []*correlation.Signal{
		{
			ID: "1", Kind: correlation.KindMemory,
			Type: correlation.TypeRWXMemory, PID: 100, ProcessName: "evil.exe",
			Timestamp: t0, Severity: 7,
		},
		{
			ID: "2", Kind: correlation.KindMemory,
			Type: correlation.TypeMemoryWrite, PID: 100, ProcessName: "evil.exe",
			Timestamp: t0.Add(time.Second), Severity: 6,
		},
		{
			ID: "3", Kind: correlation.KindMemory,
			Type: correlation.TypeProcessInjection, PID: 100, ProcessName: "evil.exe",
			Timestamp: t0.Add(2 * time.Second), Severity: 9,
		},
	}
	ctx := correlation.Group(signals)
	match := ProcessInjectionChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected ProcessInjectionChain to match")
	}
	if match.Risk != correlation.RiskCritical {
		t.Fatalf("expected CRITICAL risk, got %s", match.Risk)
	}
	if match.Likelihood != correlation.LikelihoodHigh {
		t.Fatalf("expected HIGH likelihood (observed at runtime), got %s", match.Likelihood)
	}
	if !match.Factors.ObservedAtRuntime {
		t.Fatal("Factors.ObservedAtRuntime should be true")
	}
	if len(match.Sequence) < 3 {
		t.Fatalf("expected at least 3 sequence steps, got %d", len(match.Sequence))
	}
	if len(match.Workarounds) == 0 {
		t.Fatal("chain must surface workarounds (research-time guidance)")
	}
}

func TestProcessInjectionChain_IgnoresJITRWX(t *testing.T) {
	t0 := time.Now()
	signals := []*correlation.Signal{
		{
			ID: "1", Kind: correlation.KindMemory,
			Type: correlation.TypeRWXMemory, PID: 100, ProcessName: "java.exe",
			Timestamp: t0, Severity: 7,
			Tags: []string{correlation.TagJIT},
		},
		{
			ID: "2", Kind: correlation.KindMemory,
			Type: correlation.TypeMemoryWrite, PID: 100, ProcessName: "java.exe",
			Timestamp: t0.Add(time.Second), Severity: 6,
		},
	}
	ctx := correlation.Group(signals)
	got := ProcessInjectionChain{}.Detect(ctx)
	if got != nil {
		t.Fatalf("JIT-tagged RWX should not trigger injection chain; got %+v", got)
	}
}

func TestDownloaderChain_PerProcess(t *testing.T) {
	t0 := time.Now()
	signals := []*correlation.Signal{
		{
			ID: "1", Kind: correlation.KindNetwork,
			Type: correlation.TypePublicEgress, PID: 555, ProcessName: "loader",
			Timestamp: t0, Target: "203.0.113.7:80",
		},
		{
			ID: "2", Kind: correlation.KindFile,
			Type: correlation.TypeFileDropExec, PID: 555, ProcessName: "loader",
			Timestamp: t0.Add(time.Second), Target: "C:\\temp\\stage2.exe",
		},
	}
	ctx := correlation.Group(signals)
	match := DownloaderChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected DownloaderChain to match")
	}
	if match.Risk != correlation.RiskCritical {
		t.Fatalf("per-process downloader should be CRITICAL, got %s", match.Risk)
	}
	if len(match.MITRETechniques) == 0 {
		t.Fatal("chain should surface MITRE techniques")
	}
}

func TestDownloaderChain_NoEvidence(t *testing.T) {
	ctx := correlation.Group(nil)
	got := DownloaderChain{}.Detect(ctx)
	if got != nil {
		t.Fatalf("empty context should not produce a chain, got %+v", got)
	}
}

func TestPersistenceChain_RegistryAndDrop(t *testing.T) {
	t0 := time.Now()
	signals := []*correlation.Signal{
		{
			ID: "1", Kind: correlation.KindRegistry,
			Type: correlation.TypeRegistryAutorun, Timestamp: t0,
			Target:   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\malware`,
			Evidence: []string{`Run\malware = C:\temp\stage2.exe`},
		},
		{
			ID: "2", Kind: correlation.KindFile,
			Type: correlation.TypeFileDropExec, Timestamp: t0.Add(time.Second),
			Target: `C:\temp\stage2.exe`,
		},
	}
	ctx := correlation.Group(signals)
	match := PersistenceChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected PersistenceChain to match")
	}
	if match.Risk != correlation.RiskCritical {
		t.Fatalf("persistence with backing drop should be CRITICAL, got %s", match.Risk)
	}
	if len(match.Sequence) < 2 {
		t.Fatalf("expected 2-step sequence, got %d", len(match.Sequence))
	}
}

func TestPersistenceChain_NoSetup(t *testing.T) {
	ctx := correlation.Group([]*correlation.Signal{
		{ID: "1", Kind: correlation.KindFile, Type: correlation.TypeFileDropExec},
	})
	got := PersistenceChain{}.Detect(ctx)
	if got != nil {
		t.Fatalf("drop alone should not trigger persistence chain, got %+v", got)
	}
}

func TestDataExfiltrationChain_PerProcess(t *testing.T) {
	t0 := time.Now()
	signals := []*correlation.Signal{
		{
			ID: "1", Kind: correlation.KindAudit,
			Type: correlation.TypeHardcodedSecret, Severity: 7,
			Location: correlation.Location{File: "Foo.smali"},
		},
		{
			ID: "2", Kind: correlation.KindNetwork,
			Type: correlation.TypePublicEgress, PID: 42, ProcessName: "app",
			Timestamp: t0, Target: "203.0.113.10:443", Severity: 5,
		},
	}
	// Make the secret belong to the same process as the network call so
	// the chain pairs them. We model that via a sandbox-attributed
	// runtime signal that holds the same PID.
	signals = append(signals, &correlation.Signal{
		ID: "3", Kind: correlation.KindFile,
		Type: correlation.TypeSensitiveCache, PID: 42, ProcessName: "app",
		Target: `C:\Users\app\cache\token.json`, Severity: 8,
	})
	ctx := correlation.Group(signals)
	match := DataExfiltrationChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected DataExfiltrationChain to match")
	}
	if match.Risk != correlation.RiskCritical {
		t.Fatalf("per-process exfil should be CRITICAL, got %s", match.Risk)
	}
}

func TestAuthBypassChain_NoServerValidation(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Kind: correlation.KindAudit, Type: correlation.TypeAuthGate, Severity: 5},
	}
	ctx := correlation.Group(signals)
	match := AuthBypassChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected AuthBypassChain to match")
	}
	if match.Risk != correlation.RiskHigh {
		t.Fatalf("auth gate without server validation should be HIGH, got %s", match.Risk)
	}
	if !match.Factors.Controllable {
		t.Fatal("client-side gate should be marked Controllable")
	}
	if len(match.Workarounds) == 0 {
		t.Fatal("chain must include research workarounds")
	}
}

func TestAuthBypassChain_WithServerValidation(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Kind: correlation.KindAudit, Type: correlation.TypeAuthGate, Severity: 5},
		{ID: "2", Kind: correlation.KindNetwork, Type: correlation.TypeOutboundConnection,
			Severity: 5, Timestamp: time.Now()},
	}
	ctx := correlation.Group(signals)
	match := AuthBypassChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected AuthBypassChain to match")
	}
	if match.Risk != correlation.RiskMedium {
		t.Fatalf("auth gate with runtime network should be MEDIUM, got %s", match.Risk)
	}
}

// Regression (subwaysurf): a chain built ONLY on native .so string-blob
// gates (libunity.so "isPro") must not fire at all.
func TestAuthBypassChain_NativeOnlyGatesIgnored(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Kind: correlation.KindAudit, Type: correlation.TypeAuthGate,
			Severity: 7, Confidence: 0.9,
			Location: correlation.Location{File: `lib\arm64-v8a\libunity.so`, Line: 1040}},
	}
	ctx := correlation.Group(signals)
	match := AuthBypassChain{}.Detect(ctx)
	if match != nil {
		t.Fatalf("native-only gates must not build a chain, got %+v", match)
	}
}

// Weak-only static evidence (low severity + low confidence, no runtime)
// demotes to MEDIUM instead of HIGH.
func TestAuthBypassChain_WeakEvidenceDemoted(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Kind: correlation.KindAudit, Type: correlation.TypeAuthGate,
			Severity: 2, Confidence: 0.4,
			Location: correlation.Location{File: "a.smali", Line: 98}},
	}
	ctx := correlation.Group(signals)
	match := AuthBypassChain{}.Detect(ctx)
	if match == nil {
		t.Fatal("expected chain to still match on weak smali evidence")
	}
	if match.Risk != correlation.RiskMedium {
		t.Fatalf("weak-only evidence should be MEDIUM, got %s", match.Risk)
	}
}

func TestDefaultChains_AllDetectorsPresent(t *testing.T) {
	chains := DefaultChains()
	if len(chains) < 5 {
		t.Fatalf("expected at least 5 default chains, got %d", len(chains))
	}
	seen := map[string]bool{}
	for _, c := range chains {
		seen[c.ID()] = true
	}
	for _, want := range []string{
		"process_injection_chain",
		"downloader_chain",
		"persistence_chain",
		"data_exfiltration_chain",
		"auth_bypass_chain",
	} {
		if !seen[want] {
			t.Fatalf("missing default chain %s", want)
		}
	}
}
