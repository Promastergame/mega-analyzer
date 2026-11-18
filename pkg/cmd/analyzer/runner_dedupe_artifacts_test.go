package main

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// A 4-ABI native library repeated the same finding once per lib/<abi>/ copy:
// JNI surface ×5, raw syscall ×3, numeric PIN ×2 on a single clean APK.
func TestDedupeArtifactFindingsMergesABICopies(t *testing.T) {
	findings := []types.ArtifactFinding{
		{Path: "/tmp/x/lib/arm64-v8a/libsand.so", Severity: types.SeverityInfo, Reason: "[jni] JNI native surface: 10 exported Java_* symbols"},
		{Path: "/tmp/x/lib/armeabi-v7a/libsand.so", Severity: types.SeverityInfo, Reason: "[jni] JNI native surface: 10 exported Java_* symbols"},
		{Path: "/tmp/x/lib/x86/libsand.so", Severity: types.SeverityInfo, Reason: "[jni] JNI native surface: 10 exported Java_* symbols"},
		{Path: "/tmp/x/lib/x86_64/libsand.so", Severity: types.SeverityInfo, Reason: "[jni] JNI native surface: 10 exported Java_* symbols"},
		{Path: "/tmp/x/lib/arm64-v8a/libsand.so", Severity: types.SeverityInfo, Reason: "[import] Raw syscall import: syscall() is imported"},
		{Path: "/tmp/x/lib/x86_64/libsand.so", Severity: types.SeverityInfo, Reason: "[import] Raw syscall import: syscall() is imported"},
		{Path: "/tmp/x/lib/arm64-v8a/libsand.so", Severity: types.SeverityInfo, Reason: "Standalone numeric literal", Payload: "********", Stages: []string{"native", "secret", "numeric-pin", "inventory"}},
		{Path: "/tmp/x/lib/x86/libsand.so", Severity: types.SeverityInfo, Reason: "Standalone numeric literal", Payload: "****", Stages: []string{"native", "secret", "numeric-pin", "inventory"}},
	}
	got := dedupeArtifactFindings(findings)
	// 1 JNI + 1 syscall + 2 numeric literals: the literals have different
	// payloads (8 vs 4 masked chars) so they stay separate — 4 findings.
	if len(got) != 4 {
		t.Fatalf("dedupeArtifactFindings() = %d findings, want 4", len(got))
	}
	// Only actually-merged findings (JNI surface, raw syscall) carry the
	// ABI-copy annotation; the two distinct numeric literals do not.
	if len(got) < 2 || !strings.Contains(got[0].Reason, "ABI copies of this library") ||
		!strings.Contains(got[1].Reason, "ABI copies of this library") {
		t.Error("merged findings are missing the ABI-copy annotation")
	}
	for _, f := range got[2:] {
		if strings.Contains(f.Reason, "ABI copies of this library") {
			t.Errorf("unmerged finding %q must not carry the ABI-copy annotation", f.Reason)
		}
	}
}

func TestDedupeArtifactFindingsKeepsDifferentFindings(t *testing.T) {
	findings := []types.ArtifactFinding{
		{Path: "/tmp/x/lib/arm64-v8a/liba.so", Severity: types.SeverityInfo, Reason: "[jni] JNI native surface: 10 exported Java_* symbols"},
		{Path: "/tmp/x/lib/arm64-v8a/libb.so", Severity: types.SeverityInfo, Reason: "[jni] JNI native surface: 10 exported Java_* symbols"},
	}
	got := dedupeArtifactFindings(findings)
	if len(got) != 2 {
		t.Fatalf("dedupeArtifactFindings() = %d findings, want 2 (different libraries must not merge)", len(got))
	}
	if len(dedupeArtifactFindings(nil)) != 0 || len(dedupeArtifactFindings(findings[:1])) != 1 {
		t.Fatal("dedupeArtifactFindings() must be a no-op for 0/1 findings")
	}
}
