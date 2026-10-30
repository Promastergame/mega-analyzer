package apkloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegressionJSCommentDoesNotDisableLiteralDecoding(t *testing.T) {
	dir := t.TempDir()
	code := `var endpoint = "\x68\x74\x74\x70\x73\x3a\x2f\x2fapi.example.com/v1";`
	for _, prefix := range []string{"", "// Hermes engine\n"} {
		path := filepath.Join(dir, "index.android.bundle")
		if err := os.WriteFile(path, []byte(prefix+code), 0600); err != nil {
			t.Fatal(err)
		}
		findings, err := scanBundleFile(path, dir)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range findings {
			if finding.Payload == "https://api.example.com/v1" {
				found = true
			}
		}
		if !found {
			t.Errorf("prefix=%q suppresses decoded endpoint, classification=%d", prefix, classifyBundle([]byte(prefix+code)))
		}
	}
}

func TestRegressionHBCDiscoveryUsesMagicRegardlessOfExtension(t *testing.T) {
	data := buildTestHBC(t, 96, []string{"main", "moduleA", "https://api.example.com/graphql"})
	for _, name := range []string{"index.android.bundle", "main.hbc"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		findings, err := ScanHermes(dir)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range findings {
			if finding.Payload == "https://api.example.com/graphql" {
				found = true
			}
		}
		if !found {
			t.Errorf("same valid HBC data in %s: endpoint not discovered", name)
		}
	}
}

func TestRegressionHermesMalformedBundleHasCoverageWarning(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.android.bundle"), HermesMagicLE, 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanHermes(dir)
	if err == nil && len(findings) == 0 {
		t.Fatal("truncated HBC yields no findings and nil error: indistinguishable from completed clean scan")
	}
}
