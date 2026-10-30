package jspatcher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRegressionJSMinificationPreservesOccurrences(t *testing.T) {
	scanner := NewScanner([]JSPatchCategory{CategoryServer})
	first := `const first = "203.0.113.10";`
	second := `const second = "203.0.113.20";`
	count := func(src string) int {
		n := 0
		for _, match := range scanner.ScanFile(src, "index.android.bundle") {
			if match.Rule.ID == "server_ip_literal" {
				n++
			}
		}
		return n
	}
	readable, minified := count(first+"\n"+second), count(first+second)
	if readable != 2 || minified != 2 {
		t.Fatalf("same JavaScript: multiline matches=%d, single-line matches=%d; want 2 each", readable, minified)
	}
}

func TestRegressionJSBuiltInRegexpsCompile(t *testing.T) {
	for _, rule := range AllRules {
		for _, group := range []struct {
			name     string
			patterns []string
		}{{"primary", rule.Patterns}, {"boost", rule.ContextBoosts}, {"penalty", rule.ContextPenalties}} {
			for i, pattern := range group.patterns {
				if _, err := regexp.Compile(pattern); err != nil {
					t.Errorf("%s %s[%d]: %v", rule.ID, group.name, i, err)
				}
			}
		}
	}
}

func TestRegressionJSSourceMapDoesNotSilentlyDropAppCode(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "index.android.bundle")
	var names, contents []string
	for i := 0; i < 128; i++ {
		names = append(names, fmt.Sprintf("node_modules/vendor-%d.js", i))
		contents = append(contents, "var generated = 1;")
	}
	names = append(names, "src/network.js")
	contents = append(contents, `function isPremium() { return false; }`)
	if len(NewScanner(nil).ScanFile(contents[len(contents)-1], names[len(names)-1])) == 0 {
		t.Fatal("control fixture must match when scanned directly")
	}
	doc, err := json.Marshal(map[string]any{"version": 3, "sources": names, "sourcesContent": contents})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath+".map", doc, 0600); err != nil {
		t.Fatal(err)
	}
	src := "var generated = 1;\n//# sourceMappingURL=index.android.bundle.map\n"
	if err := os.WriteFile(bundlePath, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.MinConfidence = 0
	result, err := NewPatcher(cfg).PatchFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range result.Matches {
		if match.FromSourceMap && strings.Contains(match.FilePath, "src/network.js") {
			return
		}
	}
	if len(result.Errors) == 0 {
		t.Fatal("129th source is application code: no finding, no coverage warning; scan claims 1/1 files")
	}
}
