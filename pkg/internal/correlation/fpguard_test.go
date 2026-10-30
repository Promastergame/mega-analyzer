package correlation

import (
	"strings"
	"testing"
)

func TestFPGuard_DowngradesJITRWX(t *testing.T) {
	signals := []*Signal{
		{
			Type:        TypeRWXMemory,
			Kind:        KindMemory,
			ProcessName: "java.exe",
			Severity:    9,
			Confidence:  0.9,
			Description: "executable memory allocated",
		},
	}
	FPGuard(signals)
	got := signals[0]
	if !got.HasTag(TagJIT) {
		t.Fatal("expected TagJIT to be applied to java.exe RWX")
	}
	if got.Severity > 4 {
		t.Fatalf("expected severity <= 4 for JIT RWX, got %d", got.Severity)
	}
	if got.Confidence > 0.4 {
		t.Fatalf("expected confidence <= 0.4 for JIT RWX, got %f", got.Confidence)
	}
}

func TestFPGuard_KeepsRealRWX(t *testing.T) {
	signals := []*Signal{
		{
			Type:        TypeRWXMemory,
			Kind:        KindMemory,
			ProcessName: "evil.exe",
			Severity:    9,
			Confidence:  0.9,
		},
	}
	FPGuard(signals)
	got := signals[0]
	if got.HasTag(TagJIT) {
		t.Fatal("non-JIT process should not be tagged JIT")
	}
	if got.Severity != 9 || got.Confidence != 0.9 {
		t.Fatalf("non-JIT RWX should be left alone: %+v", got)
	}
}

func TestFPGuard_DebugEndpointDormant(t *testing.T) {
	signals := []*Signal{
		{
			Type:       TypeDebugEndpoint,
			Kind:       KindAudit,
			Severity:   8,
			Confidence: 0.9,
		},
	}
	FPGuard(signals)
	got := signals[0]
	if got.Severity > 4 {
		t.Fatalf("dormant debug endpoint should be downgraded, got severity %d", got.Severity)
	}
	if got.Confidence > 0.5 {
		t.Fatalf("dormant debug endpoint should have confidence <= 0.5, got %f", got.Confidence)
	}
	if !strings.Contains(got.Description, "unreached") {
		t.Fatalf("description should mention unreached: %q", got.Description)
	}
}

func TestFPGuard_DebugEndpointExported(t *testing.T) {
	signals := []*Signal{
		{
			Type:       TypeDebugEndpoint,
			Kind:       KindAudit,
			Severity:   8,
			Confidence: 0.9,
			Tags:       []string{TagExported},
		},
	}
	FPGuard(signals)
	got := signals[0]
	if got.Severity != 8 || got.Confidence != 0.9 {
		t.Fatalf("exported debug endpoint should not be downgraded: %+v", got)
	}
}

func TestFPGuard_WebViewBridgeNoSensitive(t *testing.T) {
	signals := []*Signal{
		{
			Type:     TypeWebViewJSBridge,
			Kind:     KindAudit,
			Severity: 8,
		},
	}
	FPGuard(signals)
	got := signals[0]
	if got.Severity > 5 {
		t.Fatalf("bridge without sensitive method should cap at 5, got %d", got.Severity)
	}
}

func TestFPGuard_WebViewBridgeWithSensitive(t *testing.T) {
	signals := []*Signal{
		{
			Type:     TypeWebViewJSBridge,
			Kind:     KindAudit,
			Severity: 8,
			Tags:     []string{TagSensitiveMethod},
		},
	}
	FPGuard(signals)
	got := signals[0]
	if got.Severity != 8 {
		t.Fatalf("bridge with sensitive method should be left alone, got %d", got.Severity)
	}
}

func TestFPGuard_Idempotent(t *testing.T) {
	signals := []*Signal{
		{
			Type:        TypeRWXMemory,
			Kind:        KindMemory,
			ProcessName: "java.exe",
			Severity:    9,
		},
	}
	FPGuard(signals)
	first := *signals[0]
	FPGuard(signals)
	second := *signals[0]
	if first.Severity != second.Severity ||
		first.Description != second.Description ||
		len(first.Tags) != len(second.Tags) {
		t.Fatalf("FPGuard should be idempotent. first=%+v second=%+v", first, second)
	}
}
