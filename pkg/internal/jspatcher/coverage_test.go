package jspatcher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestURLRulesDetectHTTPAndWebSocket(t *testing.T) {
	src := `const baseURL="https://api.example.net/v1?q=one-two&x=3"; const socket=new WebSocket("wss://live.example.net/feed?x=1");`
	found := map[string]bool{}
	for _, m := range NewScanner([]JSPatchCategory{CategoryServer}).ScanFile(src, "app.js") {
		found[m.Rule.ID] = true
		if src[m.ByteStart:m.ByteEnd] != m.MatchedText {
			t.Fatalf("wrong occurrence bounds: %+v", m)
		}
	}
	for _, id := range []string{"server_base_url", "server_websocket", "server_api_url_literal"} {
		if !found[id] {
			t.Errorf("%s did not detect the real endpoint", id)
		}
	}
}

func writeCoverageMap(t *testing.T, doc any) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "index.android.bundle")
	src := "var generated=0;\n//# sourceMappingURL=index.android.bundle.map\n"
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".map", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	return path, src
}

func TestIndexedMapOffsetsUTF16AndMalformedTail(t *testing.T) {
	path, src := writeCoverageMap(t, map[string]any{"version": 3, "sections": []any{
		map[string]any{"offset": map[string]int{"line": 2, "column": 4}, "map": map[string]any{
			"version": 3, "sources": []string{"src/app.js"}, "sourcesContent": []string{"😀isPremium()"},
			"mappings": "AAAE,KAAA",
		}},
		map[string]any{"offset": map[string]int{"line": 5, "column": 0}, "map": map[string]any{
			"version": 3, "sources": []string{"src/empty.js"}, "sourcesContent": []string{""}, "mappings": "",
		}},
	}})
	sources, coverage, err := loadMappedSourcesDetailed(path, src)
	if err != nil || coverage.Status != "complete" || coverage.ScannedSources != 2 {
		t.Fatalf("indexed map: %+v %v", coverage, err)
	}
	positions := mappedPositions(sources[0], 0, 4, "😀isPremium()")
	if len(positions) != 2 || !positions[0].Exact || !positions[1].Exact || positions[0].Line != 3 || positions[0].Column != 9 || positions[1].Column != 4 {
		t.Fatalf("UTF-16 or repeated use mapping lost: %+v", positions)
	}
	mappings, err := decodeSourceMappings("AAEA,CADA,!", 1, 0, 0)
	if err == nil {
		t.Fatal("malformed mapping accepted")
	}
	positions = mappedPositions(mappedSource{Mappings: mappings[0]}, 1, 0, "x")
	if len(positions) != 1 || positions[0].Column != 1 {
		t.Fatalf("valid prefix was not sorted on error: %+v", positions)
	}
}

func TestSourceMapBudgetPrioritizesAppAndSurvivesReports(t *testing.T) {
	names, contents := make([]string, maxMappedSources+1), make([]string, maxMappedSources+1)
	for i := 0; i < maxMappedSources; i++ {
		names[i] = fmt.Sprintf("node_modules/vendor/%d.js", i)
		contents[i] = "var x=0;"
	}
	names[maxMappedSources], contents[maxMappedSources] = "src/app.js", `function isPremium(){return false;}`
	path, src := writeCoverageMap(t, map[string]any{"version": 3, "sources": names, "sourcesContent": contents})
	sources, coverage, err := loadMappedSourcesDetailed(path, src)
	if err != nil || coverage.Status != "partial" || coverage.ScannedSources != maxMappedSources || coverage.SkippedSources != 1 || !strings.HasSuffix(sources[0].Name, "src/app.js") {
		t.Fatalf("application coverage under source budget: %+v %v", coverage, err)
	}
	result := &JSPatchResult{AnalysisStatus: "partial", SourceMaps: coverage, Diagnostics: coverage.Diagnostics}
	raw, err := json.Marshal(buildJSON(result))
	if err != nil {
		t.Fatal(err)
	}
	var report ReportJSON
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.AnalysisStatus != "partial" || report.SourceMaps.SkippedSources != 1 || len(report.Diagnostics) == 0 {
		t.Fatalf("JSON lost coverage: %s", raw)
	}
	var md strings.Builder
	writeMD(&md, result)
	if !strings.Contains(md.String(), "4096 / 4097") {
		t.Fatal("Markdown lost source budget")
	}
}

func TestSourceMapByteTruncationIsExplicit(t *testing.T) {
	content := strings.Repeat("x", maxMappedSourceBytes+11)
	path, src := writeCoverageMap(t, map[string]any{"version": 3, "sources": []string{"src/large.js"}, "sourcesContent": []string{content}})
	sources, c, err := loadMappedSourcesDetailed(path, src)
	if err != nil || c.Status != "partial" || c.TruncatedSources != 1 || c.TotalBytes != int64(len(content)) || c.ScannedBytes != maxMappedSourceBytes || !sources[0].Truncated {
		t.Fatalf("byte truncation hidden: %+v %v", c, err)
	}
}

func TestSourceMapCacheInvalidatedByMappings(t *testing.T) {
	doc := map[string]any{"version": 3, "sources": []string{"src/app.js"}, "sourcesContent": []string{`function isPremium(){return false;}`}, "mappings": "AAAA"}
	path, _ := writeCoverageMap(t, doc)
	cfg := DefaultConfig()
	cfg.MinConfidence = 0
	cfg.OutputDir = filepath.Join(filepath.Dir(path), "reports")
	patcher := NewPatcher(cfg)
	first, err := patcher.PatchFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := patcher.PatchFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cached.CacheHit || len(first.Matches) == 0 || len(cached.Matches[0].GeneratedPositions) == 0 {
		t.Fatal("cache lost positions")
	}
	doc["mappings"] = "KAAA"
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(path+".map", data, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := patcher.PatchFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed.CacheHit || changed.Matches[0].GeneratedPositions[0].Column != 5 {
		t.Fatalf("stale map positions: %+v", changed)
	}
}

func TestMinifiedSiblingFunctionsAreNeverRewrittenAsOneLine(t *testing.T) {
	src := `function isPremium(){return false;}function unrelated(){return true;}`
	for _, m := range NewScanner(nil).ScanFile(src, "app.bundle") {
		if !m.Context.AmbiguousRewrite {
			t.Fatalf("sibling function context unsafe: %+v", m)
		}
		if patch := GeneratePatch(m, strings.Split(src, "\n"), ""); patch != nil {
			t.Fatalf("unsafe rewrite proposed: %+v", patch)
		}
	}
}

func TestSourceMapReferenceUsesLastCommentRegardlessOfStyle(t *testing.T) {
	src := "/*# sourceMappingURL=old.map */\nvar x=1;\n//# sourceMappingURL=new.map\n"
	if got := sourceMapReference(src); got != "new.map" {
		t.Fatalf("last map comment = %q", got)
	}
}
