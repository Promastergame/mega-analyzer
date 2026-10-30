package experimental

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSelector_Numeric(t *testing.T) {
	reg := DefaultRegistry()
	mods, err := ParseSelector("1-4", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 4 {
		t.Fatalf("want 4 modules, got %d", len(mods))
	}
}

func TestParseSelector_NamesAndRanges(t *testing.T) {
	reg := DefaultRegistry()
	cases := []struct {
		name string
		sel  string
		want int
	}{
		{"single id", "macho", 1},
		{"alias", "ios", 1},
		{"comma list", "macho,binsim", 2},
		{"range", "1-2", 2},
		{"preset all", "all", 6},
		{"preset alice", "alice", 3},
		{"preset offense", "offense", 4},
		{"mix", "alice,4", 4},
		{"whitespace", " macho , reach ", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mods, err := ParseSelector(tc.sel, reg)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sel, err)
			}
			if len(mods) != tc.want {
				ids := make([]string, len(mods))
				for i, m := range mods {
					ids[i] = m.ID()
				}
				t.Fatalf("selector %q: want %d, got %d (%v)", tc.sel, tc.want, len(mods), ids)
			}
		})
	}
}

func TestParseSelector_Empty(t *testing.T) {
	reg := DefaultRegistry()
	mods, err := ParseSelector("   ", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 0 {
		t.Fatalf("expected empty selection, got %d", len(mods))
	}
}

func TestParseSelector_Invalid(t *testing.T) {
	reg := DefaultRegistry()
	bad := []string{"99", "1-99", "nope", "1-", "-3"}
	for _, s := range bad {
		if _, err := ParseSelector(s, reg); err == nil {
			t.Errorf("expected error for selector %q", s)
		}
	}
}

func TestParseSelector_DedupOrder(t *testing.T) {
	reg := DefaultRegistry()
	mods, err := ParseSelector("aeg,reach,macho,binsim,aeg,1", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 4 {
		t.Fatalf("want 4 unique modules, got %d", len(mods))
	}
	// Verify stable registry order: macho, binsim, reach, aeg.
	wantOrder := []string{"macho", "binsim", "reach", "aeg"}
	for i, m := range mods {
		if m.ID() != wantOrder[i] {
			t.Fatalf("position %d: want %s, got %s", i, wantOrder[i], m.ID())
		}
	}
}

func TestRun_NoOpOnEmptySelection(t *testing.T) {
	res, err := Run(context.Background(), Input{}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if len(res.Modules) != 0 {
		t.Fatalf("expected empty result, got %d modules", len(res.Modules))
	}
}

func TestRegistry_LookupAlias(t *testing.T) {
	reg := DefaultRegistry()
	if _, ok := reg.Lookup("ios"); !ok {
		t.Fatal("alias 'ios' should resolve to macho")
	}
	if _, ok := reg.Lookup("EXPLOIT"); !ok {
		t.Fatal("alias 'EXPLOIT' (case insensitive) should resolve to aeg")
	}
}

// ─── module smoke tests ────────────────────────────────────────────────────

func TestMachOModule_NoMachOInTree(t *testing.T) {
	dir := testTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewMachOModule()
	res, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.ModuleID != "macho" {
		t.Fatalf("module id mismatch: %s", res.ModuleID)
	}
}

func TestBinSimModule_NoCandidates(t *testing.T) {
	dir := testTempDir(t)
	m := NewBinSimModule()
	res, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.ModuleID != "binsim" {
		t.Fatalf("module id mismatch: %s", res.ModuleID)
	}
}

func TestReachModule_NoSmali(t *testing.T) {
	dir := testTempDir(t)
	m := NewReachModule()
	res, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if res.ModuleID != "reach" {
		t.Fatalf("module id mismatch: %s", res.ModuleID)
	}
}

func TestAEGModule_GeneratesArtifactForExportedActivity(t *testing.T) {
	dir := testTempDir(t)
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.demo">
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="demo" android:host="open" />
      </intent-filter>
    </activity>
  </application>
</manifest>`
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewAEGModule()
	res, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected at least one finding, got 0; notes=%v", res.Notes)
	}
	// Verify a PoC was written.
	pocDir := filepath.Join(dir, AEGRunDirName)
	entries, err := os.ReadDir(pocDir)
	if err != nil {
		t.Fatalf("read poc dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one PoC artifact")
	}
	// Header should be present in every artifact.
	body, err := os.ReadFile(filepath.Join(pocDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Mega Analyzer") {
		t.Fatal("PoC artifact is missing the header banner")
	}
}

func TestBinSimModule_DetectsExactClone(t *testing.T) {
	dir := testTempDir(t)
	libDir := filepath.Join(dir, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, binsimMinSize+1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libfoo.so"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libfoo_copy.so"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewBinSimModule()
	res, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.ID == "binsim-exact-clone" {
			got++
		}
	}
	if got == 0 {
		t.Fatalf("expected exact-clone finding, got none; res=%+v", res.Findings)
	}
}

func TestRun_PerModuleTimeout(t *testing.T) {
	dir := testTempDir(t)
	res, err := Run(context.Background(), Input{TargetDir: dir, OutputDir: dir}, Options{
		Selected:         DefaultRegistry().All(),
		PerModuleTimeout: 0,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(res.Modules) != 6 {
		t.Fatalf("want 6 module results, got %d", len(res.Modules))
	}
}
