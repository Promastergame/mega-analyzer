package apkloader

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestDetectNativeCrackPoints_Strings(t *testing.T) {
	// A raw blob (not a real ELF/PE/Mach-O): only the string-symbol path runs,
	// which is exactly the Rust-free coverage we want to guarantee.
	var buf bytes.Buffer
	buf.WriteString("padding\x00")
	buf.WriteString("/system/bin/su\x00")
	buf.WriteString("ptrace\x00")
	buf.WriteString("nothing-interesting\x00")

	points := DetectNativeCrackPoints(buf.Bytes(), "libfoo.so")
	var root, tamper bool
	for _, p := range points {
		switch p.Category {
		case "root":
			root = true
		case "tamper":
			tamper = true
		}
		if p.Location.File != "libfoo.so" {
			t.Errorf("unexpected file %q", p.Location.File)
		}
	}
	if !root {
		t.Error("expected a root crack point for /system/bin/su")
	}
	if !tamper {
		t.Error("expected a tamper crack point for ptrace")
	}
}

func TestNativeSecretFindings(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("prefix\x00")
	buf.WriteString("AKIA1B2C3D4E5F6G7H8J\x00")
	data := buf.Bytes()

	masked := NativeSecretFindings(data, "libfoo.so", false, true)
	if len(masked) == 0 {
		t.Fatal("expected an embedded-secret finding for the AWS key")
	}
	for _, f := range masked {
		if f.Payload == "AKIA1B2C3D4E5F6G7H8J" {
			t.Error("secret must be masked in the finding payload")
		}
		if f.PayloadFull != "" {
			t.Error("PayloadFull must stay empty when reveal is false")
		}
	}

	revealed := NativeSecretFindings(data, "libfoo.so", true, true)
	var sawFull bool
	for _, f := range revealed {
		if f.PayloadFull == "AKIA1B2C3D4E5F6G7H8J" {
			sawFull = true
		}
	}
	if !sawFull {
		t.Error("expected PayloadFull to carry the unmasked secret when reveal is true")
	}
}

// TestNativeSecretFindings_NumericPin covers the short-PIN heuristic: a bare
// digit run near a credential keyword ("password:") is Medium (matching the
// Rust scan_numeric_candidates severity policy), the same shape far from any
// keyword is only Low.
func TestNativeSecretFindings_NumericPin(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("password:\x00")
	buf.WriteString("1234\x00")
	buf.WriteString(strings.Repeat("A", 200) + "\x00") // pushes "5678" outside the ±48-byte window
	buf.WriteString("5678\x00")
	data := buf.Bytes()

	findings := NativeSecretFindings(data, "libfoo.so", false, true)

	var gotMedium, gotLow bool
	for _, f := range findings {
		if !strings.Contains(f.Reason, "PIN/password") {
			continue
		}
		switch f.Severity {
		case types.SeverityMedium:
			gotMedium = true
		case types.SeverityLow:
			gotLow = true
		}
	}
	if !gotMedium {
		t.Error("expected a Medium numeric-PIN finding near the \"password:\" keyword")
	}
	if !gotLow {
		t.Error("expected a Low numeric-PIN finding with no nearby keyword")
	}
}

// TestNativeSecretFindings_NumericPinSkippedWhenRustRan covers the dedup fix:
// when includeNumericPin is false (Rust scan-native already covered the
// signal), the pure-Go fallback must not also emit numeric-PIN findings.
func TestNativeSecretFindings_NumericPinSkippedWhenRustRan(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("password:\x00")
	buf.WriteString("1234\x00")
	data := buf.Bytes()

	findings := NativeSecretFindings(data, "libfoo.so", false, false)
	for _, f := range findings {
		if strings.Contains(f.Reason, "PIN/password") {
			t.Errorf("expected no numeric-PIN finding when includeNumericPin=false, got: %+v", f)
		}
	}
}

// TestNativeSecretFindings_PlaceholderSuppressed covers the fpfilter reuse:
// llmkeys.Classify treats "@string/api_key_..." as a high-confidence secret
// (it contains the "api_key" credential indicator), but the value is really
// an Android resource reference — fpfilter's placeholder heuristic (which
// recognizes "@string/"/"@android:" as resource markers, unlike llmkeys)
// should suppress it before it becomes a finding.
func TestNativeSecretFindings_PlaceholderSuppressed(t *testing.T) {
	const resourceRef = "@string/api_key_9f8e7d6c5b4a"
	var buf bytes.Buffer
	buf.WriteString("noise\x00")
	buf.WriteString(resourceRef + "\x00")
	data := buf.Bytes()

	findings := NativeSecretFindings(data, "libfoo.so", true, true)
	for _, f := range findings {
		if f.PayloadFull == resourceRef {
			t.Errorf("expected fpfilter to suppress the Android resource-reference placeholder, got finding: %+v", f)
		}
	}
}

func TestDetectNativeCrackPoints_Empty(t *testing.T) {
	if got := DetectNativeCrackPoints(nil, "x"); got != nil {
		t.Errorf("nil data should yield no crack points, got %v", got)
	}
}

// TestNativeSecretFindings_NumericPinCap covers the report-size guardrail:
// a binary dense with standalone digit runs must stop emitting numeric-PIN
// findings at maxNumericPinFindings and instead note how many were skipped.
func TestNativeSecretFindings_NumericPinCap(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < maxNumericPinFindings+5; i++ {
		buf.WriteString("\x00")
		fmt.Fprintf(&buf, "%03d", i%1000)
	}
	data := buf.Bytes()

	findings := NativeSecretFindings(data, "libfoo.so", false, true)

	var pinCount int
	var sawTruncationNote bool
	for _, f := range findings {
		switch {
		case strings.Contains(f.Reason, "PIN/password"):
			pinCount++
		case strings.Contains(f.Reason, "omitted to keep the report readable"):
			sawTruncationNote = true
		}
	}
	if pinCount > maxNumericPinFindings {
		t.Errorf("expected at most %d numeric-PIN findings, got %d", maxNumericPinFindings, pinCount)
	}
	if !sawTruncationNote {
		t.Error("expected a truncation note when candidates exceed the cap")
	}
}
