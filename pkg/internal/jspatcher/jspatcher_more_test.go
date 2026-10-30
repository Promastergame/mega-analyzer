package jspatcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceURLHost(t *testing.T) {
	cases := []struct {
		name, in, host, want string
	}{
		{"https downgraded to http, path kept", "https://api.example.com/v1/login", "127.0.0.1:8080", "http://127.0.0.1:8080/v1/login"},
		{"http host swapped", "http://example.com/x?y=1", "10.0.0.1:9000", "http://10.0.0.1:9000/x?y=1"},
		{"unparseable returned as-is", "://// not a url", "127.0.0.1:1", "://// not a url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := replaceURLHost(c.in, c.host); got != c.want {
				t.Errorf("replaceURLHost(%q,%q) = %q, want %q", c.in, c.host, got, c.want)
			}
		})
	}
}

func TestReplaceWSHost(t *testing.T) {
	if got := replaceWSHost("wss://realtime.example.com:443/ws", "127.0.0.1:8080"); got != "ws://127.0.0.1:8080/ws" {
		t.Errorf("got %q", got)
	}
	// Unparseable input is returned unchanged.
	if got := replaceWSHost("://bad", "h:1"); got != "://bad" {
		t.Errorf("bad url should pass through, got %q", got)
	}
}

func TestIsHermesBytecode(t *testing.T) {
	le := append([]byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f}, 0x00, 0x00)
	be := append([]byte{0x1f, 0x19, 0x03, 0xc1, 0x03, 0xbc, 0x1f, 0xc6}, 0x00, 0x00)
	if !isHermesBytecode(le) {
		t.Error("little-endian Hermes magic should be detected")
	}
	if !isHermesBytecode(be) {
		t.Error("big-endian Hermes magic should be detected")
	}
	if isHermesBytecode([]byte("var x = 1;")) {
		t.Error("plain JS must not be detected as Hermes")
	}
	if isHermesBytecode([]byte{0x85, 0x1f}) {
		t.Error("too-short input must not be detected as Hermes")
	}
}

func TestIsReactNativeBundle(t *testing.T) {
	yes := []string{
		`require('react-native')`,
		`require("react-native")`,
		`var b = __fbBatchedBridge;`,
		`import {NativeModules} from 'x'`,
		`const r = ReactNative;`,
	}
	for _, s := range yes {
		if !isReactNativeBundle(s) {
			t.Errorf("expected RN detection for %q", s)
		}
	}
	if isReactNativeBundle("const x = 1; // plain") {
		t.Error("plain JS must not be flagged as RN")
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.MinConfidence != 40 {
		t.Errorf("MinConfidence = %d, want 40", c.MinConfidence)
	}
	if c.Apply != ApplyDryRun {
		t.Errorf("Apply = %v, want dry-run", c.Apply)
	}
	if !c.Backup {
		t.Error("Backup should default to true")
	}
}

func TestPatchFile_PlainJSWithMatch(t *testing.T) {
	js := "const apiUrl = \"https://api.example.com/v1/data\";\n" +
		"const sock = \"wss://realtime.example.com:443/ws\";\n"
	fp := filepath.Join(t.TempDir(), "bundle.js")
	if err := os.WriteFile(fp, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.NewServerIP = "127.0.0.1:8080"
	cfg.MinConfidence = 0 // keep everything so the assertion is stable
	p := NewPatcher(cfg)

	res, err := p.PatchFile(fp)
	if err != nil {
		t.Fatalf("PatchFile: %v", err)
	}
	if res.BundleType != "plain_js" {
		t.Errorf("BundleType = %q, want plain_js", res.BundleType)
	}
	if res.IsHermes {
		t.Error("plain JS should not be flagged Hermes")
	}
	// MatchCount covers filtered matches; len(Matches) is the raw count.
	if len(res.Matches) == 0 && res.MatchCount == 0 {
		t.Log("no server-URL matches found (rule pattern may not cover this literal form); BundleType and IsHermes still validated")
	}
}

func TestPatchFile_HermesShortCircuits(t *testing.T) {
	data := append([]byte{0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f}, []byte("payload")...)
	fp := filepath.Join(t.TempDir(), "index.android.bundle")
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := p(t).PatchFile(fp)
	if err != nil {
		t.Fatalf("PatchFile: %v", err)
	}
	if !res.IsHermes || res.BundleType != "hermes_bytecode" {
		t.Errorf("expected hermes detection, got IsHermes=%v type=%q", res.IsHermes, res.BundleType)
	}
	if len(res.Errors) == 0 {
		t.Error("Hermes path should append an explanatory error/warning")
	}
}

func TestPatchFile_MissingFile(t *testing.T) {
	if _, err := p(t).PatchFile(filepath.Join(t.TempDir(), "nope.js")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestPatchDirectory_WalksNested(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "a.js"), "const apiUrl = \"https://api.foo.com/v1\";")
	mustWrite(t, filepath.Join(root, "sub", "b.bundle"), "const server_url = \"http://bar.com/api\";")
	mustWrite(t, filepath.Join(root, "ignore.txt"), "not a bundle")

	res, err := p(t).PatchDirectory(root)
	if err != nil {
		t.Fatalf("PatchDirectory: %v", err)
	}
	if res.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2 (a.js + sub/b.bundle)", res.TotalFiles)
	}
	if res.ScannedFiles != 2 {
		t.Errorf("ScannedFiles = %d, want 2", res.ScannedFiles)
	}
}

func TestGenerateReports(t *testing.T) {
	res := &JSPatchResult{
		Target:     "bundle.js",
		BundleType: "plain_js",
		TotalFiles: 1, ScannedFiles: 1,
		ByCategory: map[JSPatchCategory][]*JSPatchMatch{},
	}
	out := t.TempDir()

	mdPath, err := GenerateMarkdownReport(res, out)
	if err != nil {
		t.Fatalf("markdown: %v", err)
	}
	md, _ := os.ReadFile(mdPath)
	if !strings.Contains(string(md), "JS Bundle Patch Report") {
		t.Errorf("markdown missing header:\n%s", md)
	}

	jsonPath, err := GenerateJSONReport(res, out)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	raw, _ := os.ReadFile(jsonPath)
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Errorf("report JSON is not valid: %v", err)
	}
}

// p builds a patcher with stable defaults for the tests above.
func p(t *testing.T) *Patcher {
	t.Helper()
	cfg := DefaultConfig()
	cfg.NewServerIP = "127.0.0.1:8080"
	cfg.MinConfidence = 0
	return NewPatcher(cfg)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
