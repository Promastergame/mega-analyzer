package piracy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func findPiracyConfigPathForTest(t *testing.T) string {
	t.Helper()

	// go test runs with the package directory as cwd, so use a small fallback search.
	paths := []string{
		filepath.FromSlash("../configs/piracy_sites.json"),
		filepath.FromSlash("../../configs/piracy_sites.json"),
		filepath.FromSlash("../../../internal/configs/piracy_sites.json"),
		filepath.FromSlash("../../../configs/piracy_sites.json"),
		filepath.FromSlash("../../../piracy_sites.json"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	t.Fatalf("piracy_sites.json not found from cwd")
	return ""
}

func TestDetectorFromFile_DoesNotMatchShortAliasInsideWord_LP(t *testing.T) {
	d, err := NewDetectorFromFile(findPiracyConfigPathForTest(t))
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Previously "lp" as a substring alias could match inside "alpha".
	content := []byte("alpha")
	res, err := d.Analyze(context.Background(), "classes.smali", content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	for _, f := range res.Findings {
		if f.Source == "Lucky Patcher" {
			t.Fatalf("unexpected Lucky Patcher finding: pattern=%q desc=%q", f.Pattern, f.Description)
		}
	}
}

func TestDetectorFromFile_DoesNotMatchShortAliasInsideWord_GG(t *testing.T) {
	d, err := NewDetectorFromFile(findPiracyConfigPathForTest(t))
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Previously "gg" as a substring alias could match inside "egg".
	content := []byte("egg")
	res, err := d.Analyze(context.Background(), "classes.smali", content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	for _, f := range res.Findings {
		if f.Source == "Game Guardian" {
			t.Fatalf("unexpected Game Guardian finding: pattern=%q desc=%q", f.Pattern, f.Description)
		}
	}
}

func TestConfiguredWordIndicatorsRejectSubstrings(t *testing.T) {
	d, err := NewDetectorFromFile(findPiracyConfigPathForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text, pattern string
		want          bool
	}{
		{"SafeKeyGenerator", "keygen", false}, {"keygen", "keygen", true},
		{"BackportedFixManager", "xmanager", false}, {"xmanager", "xmanager", true},
		{"micrograms", "microg", false}, {"microg", "microg", true},
	} {
		res, err := d.Analyze(context.Background(), "classes.smali", []byte(tc.text), types.FileTypeSmali)
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, f := range res.Findings {
			if f.Pattern == tc.pattern {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%q / %q: got %v want %v", tc.text, tc.pattern, got, tc.want)
		}
	}
}
