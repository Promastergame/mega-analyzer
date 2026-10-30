package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/sbom"
	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/internal/verdict"
	"mega-analyzer/pkg/knownset"
)

// testTempDir — тот же контракт, что testing.T.TempDir, плюс ретраи
// транзиентных виндовых ошибок cleanup (см. pkg/internal/testutil).
func testTempDir(t *testing.T) string {
	t.Helper()
	return testutil.TempDir(t)
}

func TestKnownSetFlagParsing(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"-known-set", "bundle.set", "./app"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.KnownSet != "bundle.set" {
		t.Fatalf("flag not parsed: %+v", opts)
	}
	opts, err = NewCLIParser().Parse([]string{"./app"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.KnownSet != "" {
		t.Fatalf("default must be off (opt-in): %+v", opts)
	}
}

func TestKnownSetValidation(t *testing.T) {
	opts := &CLIOptions{KnownSet: filepath.Join(testTempDir(t), "nope.set")}
	if err := opts.Validate(); err == nil {
		t.Fatal("missing bundle must be rejected")
	}
	opts = &CLIOptions{KnownSet: testTempDir(t)}
	if err := opts.Validate(); err == nil {
		t.Fatal("directory must be rejected")
	}
}

// buildTestBundle собирает набор с одним bad-sha и одним good-sha.
func buildTestBundle(t *testing.T, badHex, goodHex string) string {
	t.Helper()
	b, err := knownset.NewBuilder(0.01)
	if err != nil {
		t.Fatal(err)
	}
	badKey, ok := knownset.KeySHA256(badHex)
	if !ok || !b.AddBad(badKey) {
		t.Fatal("bad key not accepted")
	}
	goodKey, ok := knownset.KeySHA256(goodHex)
	if !ok || !b.AddGood(goodKey) {
		t.Fatal("good key not accepted")
	}
	res, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(testTempDir(t), "known.set")
	if err := res.Bundle.Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func shaHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func cleanVerdictState(t *testing.T) {
	t.Helper()
	verdict.ResetDegradations()
	t.Cleanup(verdict.ResetDegradations)
}

func scoredResult() *types.AnalysisResult {
	res := types.NewAnalysisResult("knownset-test")
	res.Stats.TotalFiles, res.Stats.AnalyzedFiles = 1, 1
	return res
}

func TestKnownSetBadFileAlerts(t *testing.T) {
	cleanVerdictState(t)
	badContent := []byte("evil-bytes")
	badHex := shaHex(badContent)
	path := buildTestBundle(t, badHex, shaHex([]byte("good-bytes")))

	target := filepath.Join(testTempDir(t), "evil.apk")
	if err := os.WriteFile(target, badContent, 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{opts: &CLIOptions{KnownSet: path}}
	res := scoredResult()
	a.applyKnownSetFileHash(res, target)

	if len(res.Findings) != 1 {
		t.Fatalf("want exactly 1 finding (append-only, no skip), got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Kind != finding.KindMalware || f.Severity != "critical" || f.Category != "known_bad" {
		t.Fatalf("bad hit must be loud: %+v", f)
	}
	if res.FindingsByKind[finding.KindMalware] != 1 {
		t.Fatalf("FindingsByKind not maintained: %+v", res.FindingsByKind)
	}

	// Громкий алерт участвует в CI-гейте.
	gated := &App{opts: &CLIOptions{ExitCodes: true, FailOn: "critical"}}
	gated.assessExit(res)
	if gated.ExitCode() != 1 {
		t.Fatalf("known-bad must gate CI with exit 1, got %d", gated.ExitCode())
	}
}

func TestKnownSetGoodFileIsNoteOnly(t *testing.T) {
	cleanVerdictState(t)
	goodContent := []byte("good-bytes")
	goodHex := shaHex(goodContent)
	path := buildTestBundle(t, shaHex([]byte("evil-bytes")), goodHex)

	target := filepath.Join(testTempDir(t), "good.apk")
	if err := os.WriteFile(target, goodContent, 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{opts: &CLIOptions{KnownSet: path}}
	res := scoredResult()
	a.applyKnownSetFileHash(res, target)

	if len(res.Findings) != 1 {
		t.Fatalf("want 1 info note, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Kind != finding.KindInventory || f.Severity != "info" || f.Category != "known_good" {
		t.Fatalf("good hit must be a note, never an alert: %+v", f)
	}

	gated := &App{opts: &CLIOptions{ExitCodes: true, FailOn: "critical"}}
	gated.assessExit(res)
	if gated.ExitCode() != 0 {
		t.Fatalf("known-good must not gate CI, got %d", gated.ExitCode())
	}
}

func TestKnownSetSkipsNothing(t *testing.T) {
	cleanVerdictState(t)
	path := buildTestBundle(t, shaHex([]byte("evil")), shaHex([]byte("good")))
	a := &App{opts: &CLIOptions{KnownSet: path}}

	// Неизвестный sha: находок нет, паники нет, анализ продолжается.
	unknown := filepath.Join(testTempDir(t), "unknown.apk")
	if err := os.WriteFile(unknown, []byte("stranger"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := scoredResult()
	a.applyKnownSetFileHash(res, unknown)
	if len(res.Findings) != 0 {
		t.Fatalf("unknown sha must add nothing, got %+v", res.Findings)
	}

	// Каталог: хеша нет — тоже ничего, без ошибок.
	dirRes := scoredResult()
	a.applyKnownSetFileHash(dirRes, testTempDir(t))
	if len(dirRes.Findings) != 0 {
		t.Fatalf("directory target must add nothing, got %+v", dirRes.Findings)
	}

	// Флаг выключен: полный no-op.
	off := &App{opts: &CLIOptions{}}
	offRes := scoredResult()
	off.applyKnownSetFileHash(offRes, unknown)
	if len(offRes.Findings) != 0 {
		t.Fatalf("disabled flag must be a no-op, got %+v", offRes.Findings)
	}
}

func TestKnownSetBadBeatsGood(t *testing.T) {
	cleanVerdictState(t)
	content := []byte("conflicted")
	hexSum := shaHex(content)
	b, err := knownset.NewBuilder(0.01)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := knownset.KeySHA256(hexSum)
	b.AddGood(key)
	b.AddBad(key)
	built, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.Conflicts != 1 {
		t.Fatalf("want 1 conflict resolved to bad, got %d", built.Conflicts)
	}
	path := filepath.Join(testTempDir(t), "known.set")
	if err := built.Bundle.Save(path); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(testTempDir(t), "c.apk")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{opts: &CLIOptions{KnownSet: path}}
	res := scoredResult()
	a.applyKnownSetFileHash(res, target)
	if len(res.Findings) != 1 || res.Findings[0].Severity != "critical" {
		t.Fatalf("conflict must resolve to loud bad: %+v", res.Findings)
	}
}

func TestKnownSetSBOMVerdicts(t *testing.T) {
	cleanVerdictState(t)
	b, err := knownset.NewBuilder(0.01)
	if err != nil {
		t.Fatal(err)
	}
	badPURL := "pkg:maven/com.evil/bad@9.9"
	goodPURL := "pkg:maven/com.good/ok@1.0"
	badKey, ok := knownset.KeyPURL(badPURL)
	if !ok || !b.AddBad(badKey) {
		t.Fatalf("bad purl key not accepted: %q", badPURL)
	}
	goodKey, ok := knownset.KeyPURL(goodPURL)
	if !ok || !b.AddGood(goodKey) {
		t.Fatalf("good purl key not accepted: %q", goodPURL)
	}
	built, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(testTempDir(t), "known.set")
	if err := built.Bundle.Save(path); err != nil {
		t.Fatal(err)
	}

	a := &App{opts: &CLIOptions{KnownSet: path}}
	res := scoredResult()
	a.applyKnownSetSBOM(res, []sbom.Dependency{
		{Group: "com.evil", Name: "bad", Version: "9.9", Raw: "com.evil:bad@9.9", PURL: badPURL},
		{Group: "com.good", Name: "ok", Version: "1.0", Raw: "com.good:ok@1.0", PURL: goodPURL},
		{Group: "com.plain", Name: "lib", Version: "2.0", Raw: "com.plain:lib@2.0", PURL: "pkg:maven/com.plain/lib@2.0"},
		{Group: "x", Name: "nopurl", Version: "1", Raw: "x:nopurl@1"},
	})
	if len(res.Findings) != 2 {
		t.Fatalf("want bad alert + good note (unknown and purl-less skipped), got %+v", res.Findings)
	}
	var sawBad, sawGood bool
	for _, f := range res.Findings {
		switch f.Severity {
		case "critical":
			if f.Category != "known_bad" || f.Kind != finding.KindMalware {
				t.Fatalf("bad purl finding malformed: %+v", f)
			}
			sawBad = true
		case "info":
			if f.Category != "known_good" || f.Kind != finding.KindInventory {
				t.Fatalf("good purl finding malformed: %+v", f)
			}
			sawGood = true
		default:
			t.Fatalf("unexpected severity: %+v", f)
		}
	}
	if !sawBad || !sawGood {
		t.Fatalf("want both bad and good verdicts, got %+v", res.Findings)
	}
}
