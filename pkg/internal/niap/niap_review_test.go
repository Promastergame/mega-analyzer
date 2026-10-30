package niap

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// Review round: score-weighted verdict, nested-manifest parity between the
// directory and zip paths.

func reviewTarget(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReviewVerdictFollowsScore(t *testing.T) {
	dir := reviewTarget(t, map[string]string{"a.smali": "invoke evilcall()V"})
	cases := []struct {
		name     string
		severity int
		want     string
	}{
		{"single critical finding fails the target", 12, "non-compliant"},
		{"single low finding stays mostly compliant", 3, "mostly compliant"},
	}
	for _, tc := range cases {
		rules := []Rule{{
			ID: "ANTI.1", Type: "code", Polarity: PolarityNegative,
			Severity: tc.severity, Message: "m", Choice: [][]string{{"evilcall"}},
		}}
		rep, err := AnalyzeWithRules(dir, rules)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Verdict != tc.want {
			t.Errorf("%s: verdict = %q, want %q (score %d)",
				tc.name, rep.Verdict, tc.want, rep.Score)
		}
	}

	clean := reviewTarget(t, map[string]string{"a.smali": "invoke goodcall()V"})
	rules := []Rule{{
		ID: "ANTI.1", Type: "code", Polarity: PolarityNegative,
		Severity: 12, Message: "m", Choice: [][]string{{"evilcall"}},
	}}
	rep, err := AnalyzeWithRules(clean, rules)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "compliant" || rep.Score != 0 {
		t.Errorf("clean target: verdict = %q score = %d, want compliant/0",
			rep.Verdict, rep.Score)
	}
}

func TestReviewZipNestedManifest(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "decompiled.zip")
	f, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, e := range []struct{ name, body string }{
		{"sub/AndroidManifest.xml", `<manifest><uses-permission android:name="android.permission.INTERNET"/></manifest>`},
		{"smali/a.smali", "class public La;"},
	} {
		fw, err := w.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	rules := []Rule{{
		ID: "MAN.1", Type: "manifest", Polarity: PolarityPositive,
		Message: "m", Choice: [][]string{{`android\.permission\.INTERNET`}},
	}}
	rep, err := AnalyzeWithRules(zp, rules)
	if err != nil {
		t.Fatal(err)
	}
	if m := findMatch(t, rep, "MAN.1"); m.Status != StatusPassed {
		t.Errorf("nested zip manifest: status = %q, want %q", m.Status, StatusPassed)
	}
}
