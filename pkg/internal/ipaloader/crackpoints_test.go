package ipaloader

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractPrintableStrings(t *testing.T) {
	data := []byte("ab\x00verifyReceipt\x00xy")
	got := extractPrintableStrings(data, 5)
	found := false
	for _, s := range got {
		if s == "verifyReceipt" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected verifyReceipt in %v", got)
	}
}

func TestExtractPrintableStringsLimit(t *testing.T) {
	data := []byte("aaaaa\x00bbbbb\x00ccccc\x00ddddd")
	got := extractPrintableStringsLimited(data, 5, 2)
	if len(got) != 2 {
		t.Errorf("expected cap of 2, got %d (%v)", len(got), got)
	}
}

func TestEntitlementKeys(t *testing.T) {
	data := []byte(`<key>com.apple.developer.in-app-payments</key><array/>`)
	keys := entitlementKeys(data)
	if len(keys) != 1 || keys[0] != "com.apple.developer.in-app-payments" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestEntitlementKeysFiltersNonEntitlements(t *testing.T) {
	// A bare Info.plist key (no dot, not allow-listed) must not be treated as
	// an entitlement.
	data := []byte(`<key>CFBundleIdentifier</key><key>get-task-allow</key>`)
	keys := entitlementKeys(data)
	for _, k := range keys {
		if k == "CFBundleIdentifier" {
			t.Errorf("CFBundleIdentifier should not be treated as an entitlement: %v", keys)
		}
	}
	var hasAllow bool
	for _, k := range keys {
		if k == "get-task-allow" {
			hasAllow = true
		}
	}
	if !hasAllow {
		t.Errorf("expected allow-listed dotless entitlement to be kept: %v", keys)
	}
}

func TestCrackPointsForIPA(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Payload", "App.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Mach-O thin 64-bit LE magic + interesting strings. The bytes are not a
	// valid Mach-O, so symbol parsing is skipped and the string path runs.
	bin := append([]byte{0xCF, 0xFA, 0xED, 0xFE},
		[]byte("\x00verifyReceipt\x00/Applications/Cydia.app\x00")...)
	if err := os.WriteFile(filepath.Join(appDir, "App"), bin, 0o644); err != nil {
		t.Fatal(err)
	}

	points, _ := CrackPointsForIPA(context.Background(), dir, "com.app")
	var billing, tamper bool
	for _, p := range points {
		switch p.Category {
		case "billing":
			billing = true
		case "tamper":
			tamper = true
		}
		if p.Suggestion == "" {
			t.Errorf("iOS crack point %q is missing guidance", p.Method)
		}
	}
	if !billing {
		t.Error("expected a billing crack point for verifyReceipt")
	}
	if !tamper {
		t.Error("expected a tamper crack point for Cydia")
	}
}

// TestMachoSecretsInsightsSummary verifies that multiple embedded credentials
// produce both per-secret findings and a single aggregate insights summary.
func TestMachoSecretsInsightsSummary(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Payload", "App.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Mach-O magic followed by two AWS keys and a GitHub token, each isolated by
	// NUL bytes so the string extractor recovers them intact.
	bin := append([]byte{0xCF, 0xFA, 0xED, 0xFE},
		[]byte("\x00AKIA1B2C3D4E5F6G7H8J\x00AKIA9Z8Y7X6W5V4U3T2S\x00ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8\x00")...)
	if err := os.WriteFile(filepath.Join(appDir, "App"), bin, 0o644); err != nil {
		t.Fatal(err)
	}

	_, findings := CrackPointsForIPA(context.Background(), dir, "com.app")

	var secretCount, summaryCount int
	for _, f := range findings {
		hasInsights := false
		isSecret := false
		for _, s := range f.Stages {
			if s == "insights" {
				hasInsights = true
			}
			if s == "secret" {
				isSecret = true
			}
		}
		if hasInsights {
			summaryCount++
			if !strings.Contains(f.Reason, "Embedded-secret summary") {
				t.Errorf("summary finding has unexpected reason: %q", f.Reason)
			}
			if strings.Contains(f.Reason, "AKIA") {
				t.Error("summary finding must not contain raw credential values")
			}
		} else if isSecret {
			secretCount++
		}
	}
	if secretCount < 2 {
		t.Errorf("expected at least 2 per-secret findings, got %d", secretCount)
	}
	if summaryCount != 1 {
		t.Errorf("expected exactly 1 insights summary finding, got %d", summaryCount)
	}
}

// TestCrackPointsForIPA_ContextCancel ensures a cancelled context short-circuits
// the scan without panicking.
func TestCrackPointsForIPA_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Payload", "App.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := append([]byte{0xCF, 0xFA, 0xED, 0xFE}, []byte("\x00verifyReceipt\x00")...)
	if err := os.WriteFile(filepath.Join(appDir, "App"), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Should not panic; results may be empty.
	_, _ = CrackPointsForIPA(ctx, dir, "com.app")
}
