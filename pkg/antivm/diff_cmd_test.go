package antivm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeStatePair writes before/after JSON into a fresh temp dir and returns the
// dir plus the two file paths.
func writeStatePair(t *testing.T, before, after string) (dir, bPath, aPath string) {
	t.Helper()
	dir = t.TempDir()
	bPath = filepath.Join(dir, "before.json")
	aPath = filepath.Join(dir, "after.json")
	if err := os.WriteFile(bPath, []byte(before), 0o644); err != nil {
		t.Fatalf("write before: %v", err)
	}
	if err := os.WriteFile(aPath, []byte(after), 0o644); err != nil {
		t.Fatalf("write after: %v", err)
	}
	return dir, bPath, aPath
}

func TestSessionDiff_CleanRun_JSON(t *testing.T) {
	_, b, a := writeStatePair(t,
		`{"ro.product.model":"Pixel 7","ro.hardware":"exynos990"}`,
		`{"ro.product.model":"Pixel 7 Pro","ro.hardware":"exynos990"}`,
	)
	code := Run([]string{"session", "diff", "--before", b, "--after", a, "--format", "json"})
	if code != 0 {
		t.Errorf("clean diff returned %d, want 0", code)
	}
}

func TestSessionDiff_SessionDir(t *testing.T) {
	dir, _, _ := writeStatePair(t,
		`{"ro.hardware":"exynos990"}`,
		`{"ro.hardware":"exynos990"}`,
	)
	code := Run([]string{"session", "diff", "--session", dir})
	if code != 0 {
		t.Errorf("session-dir diff returned %d, want 0", code)
	}
}

func TestSessionDiff_DetectsResidue_FailOn(t *testing.T) {
	// A goldfish tell survives into the after-state: --fail-on-residue trips.
	_, b, a := writeStatePair(t,
		`{"ro.hardware":"exynos990"}`,
		`{"ro.hardware":"goldfish","net.eth0.mac":"52:54:00:12:34:56"}`,
	)
	code := Run([]string{"session", "diff", "--before", b, "--after", a, "--fail-on-residue"})
	if code != 1 {
		t.Errorf("residue diff returned %d, want 1", code)
	}
}

func TestSessionDiff_CleanAfter_NoFail(t *testing.T) {
	_, b, a := writeStatePair(t,
		`{"ro.hardware":"exynos990"}`,
		`{"ro.hardware":"exynos990","ro.product.model":"Pixel 8"}`,
	)
	code := Run([]string{"session", "diff", "--before", b, "--after", a, "--fail-on-residue"})
	if code != 0 {
		t.Errorf("clean after with --fail-on-residue returned %d, want 0", code)
	}
}

func TestSessionDiff_MissingArgs(t *testing.T) {
	if code := Run([]string{"session", "diff"}); code != 2 {
		t.Errorf("missing args returned %d, want 2", code)
	}
}

func TestSessionDiff_BadFormat(t *testing.T) {
	_, b, a := writeStatePair(t, `{"a":1}`, `{"a":2}`)
	if code := Run([]string{"session", "diff", "--before", b, "--after", a, "--format", "xml"}); code != 2 {
		t.Errorf("bad format returned %d, want 2", code)
	}
}

func TestFlattenJSON_NestedAndArrays(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(`{"build":{"tags":"release-keys"},"sensors":["accel","gyro"],"api":34,"root":false}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	flat := map[string]string{}
	flattenJSON("", v, flat)
	cases := map[string]string{
		"build.tags": "release-keys",
		"sensors[0]": "accel",
		"sensors[1]": "gyro",
		"api":        "34",
		"root":       "false",
	}
	for k, want := range cases {
		if got := flat[k]; got != want {
			t.Errorf("flat[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestDiffStates_AddRemoveChange(t *testing.T) {
	before := map[string]string{"keep": "x", "drop": "y", "mod": "1"}
	after := map[string]string{"keep": "x", "mod": "2", "new": "z"}
	d := diffStates(before, after)
	if len(d.Added) != 1 || d.Added[0].Path != "new" {
		t.Errorf("added = %+v, want [new]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Path != "drop" {
		t.Errorf("removed = %+v, want [drop]", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Before != "1" || d.Changed[0].After != "2" {
		t.Errorf("changed = %+v, want mod 1=>2", d.Changed)
	}
}

func TestScanResidue_MatchesKnownTells(t *testing.T) {
	flat := map[string]string{
		"ro.hardware":  "goldfish",
		"net.eth0.mac": "52:54:00:AB:CD:EF",
		"ro.product":   "Pixel 7", // clean
	}
	findings := scanResidue(flat)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	if residueScore(findings) <= 0 {
		t.Errorf("exposure score should be > 0 with residual tells")
	}
}

func TestScanResidue_SingleFindingPerPath(t *testing.T) {
	// "/dev/qemu_pipe" contains both "qemu" and "/dev/qemu_pipe"; only the
	// highest-severity indicator should be reported for the path.
	flat := map[string]string{"artifact": "/dev/qemu_pipe"}
	findings := scanResidue(flat)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Severity < 0.9 {
		t.Errorf("expected highest-severity indicator, got %+v", findings[0])
	}
}

func TestResidueScore_CleanIsZero(t *testing.T) {
	if s := residueScore(nil); s != 0 {
		t.Errorf("clean score = %v, want 0", s)
	}
}

func TestScanResidueRecognizesEnabledFlagsAndFilePresence(t *testing.T) {
	flat := map[string]string{
		"props.ro.kernel.qemu":                "1",
		"props.ro.boot.qemu":                  "0",
		"extra.file:/dev/qemu_pipe":           "yes",
		"extra.file:/dev/socket/qemud":        "no",
		"extra.unreadable:/dev/goldfish_pipe": "qemu probe failed",
		"props.init.svc.goldfish-logcat": "running",
		"props.init.svc.goldfish-setup": "stopped",
	}
	findings := scanResidue(flat)
	if len(findings) != 3 {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestSessionDiffRejectsInvalidThreshold(t *testing.T) {
	for _, threshold := range []string{"-1", "101", "NaN", "+Inf"} {
		if code := Run([]string{"session", "diff", "--residue-threshold", threshold}); code != 2 {
			t.Fatalf("threshold %s returned %d", threshold, code)
		}
	}
}
