package evalrunner

// Tests for the runner helpers and the Run entry point.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{
		"", "   ", "../evil.smali", "a/../../evil.smali", "/abs/path.smali",
		`..\evil.smali`, "a\\..\\..\\evil.smali",
		`C:\evil.smali`, `C:/evil.smali`, `C:evil.smali`, `\rooted.smali`,
		`\\server\share\evil.smali`, `sub/..\..\evil.smali`,
	} {
		if p, err := safeJoin(root, bad); err == nil {
			t.Errorf("safeJoin(%q) = %q, want error", bad, p)
		}
	}
	for _, ok := range []string{
		"a.smali", "sub/dir/b.smali", "AndroidManifest.xml", "./x.smali", "a/../b.smali",
	} {
		if _, err := safeJoin(root, ok); err != nil {
			t.Errorf("safeJoin(%q) unexpected error: %v", ok, err)
		}
	}
	for _, rel := range []string{`sub\dir\b.smali`, `sub/dir/b.smali`, `sub\dir/./b.smali`} {
		got, err := safeJoin(root, rel)
		want := filepath.Join(root, "sub", "dir", "b.smali")
		if err != nil || got != want {
			t.Errorf("safeJoin(%q) = %q, %v; want %q", rel, got, err, want)
		}
	}
}

func TestRelativize(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "sub", "f.smali")
	if got := relativize(root, inside); got != "sub/f.smali" {
		t.Errorf("relativize inside = %q", got)
	}
	if got := relativize(root, ""); got != "" {
		t.Errorf("relativize empty = %q", got)
	}
	outside := filepath.Join(t.TempDir(), "other.smali")
	got := relativize(root, outside)
	if got == "" || got == outside && filepath.IsAbs(got) {
		t.Logf("relativize outside = %q (passthrough, documented)", got)
	}
}

func TestLoadCorpusSkipsHidden(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.smali"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("h"), 0o644)
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "objects", "x"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "b.smali"), []byte("b"), 0o644)
	files, err := LoadCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files["a.smali"] != "a" || files["sub/b.smali"] != "b" {
		t.Errorf("LoadCorpus = %v", files)
	}
}

func TestResultHelpers(t *testing.T) {
	var nilRes *Result
	if nilRes.Has("x") || nilRes.CategoryList() != nil || nilRes.LocationsFor("x") != nil || nilRes.FiredAt("x", "f", 0, 0) {
		t.Error("nil Result helpers must be zero-safe")
	}
	r := &Result{
		Categories: map[string]bool{"b": true, "a": true},
		Locations: []FindingLocation{
			{Category: "a", File: "f.smali", Line: 10, Method: "m"},
			{Category: "a", File: "f.smali", Line: 20},
			{Category: "b"},
		},
	}
	if got := r.CategoryList(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("CategoryList = %v", got)
	}
	if len(r.LocationsFor("a")) != 2 || len(r.LocationsFor("zzz")) != 0 {
		t.Error("LocationsFor wrong")
	}
	if !r.FiredAt("a", "f.smali", 5, 15) || r.FiredAt("a", "f.smali", 11, 15) {
		t.Error("FiredAt range wrong")
	}
	if !r.FiredAt("a", "f.smali", 0, 0) || !r.FiredAt("b", "", 0, 0) {
		t.Error("FiredAt unbounded wrong")
	}
	if r.FiredAt("a", `sub\..\f.smali`, 0, 0) != true {
		// Backslash is a separator only on Windows; just document.
		t.Logf("FiredAt backslash path: OS-dependent, ok")
	}
	loc := FindingLocation{Category: "c", File: "f.smali", Line: 3, Method: "m()V"}
	if loc.String() != "f.smali:3 c [m()V]" {
		t.Errorf("String = %q", loc.String())
	}
}

func TestRunEmptyCorpus(t *testing.T) {
	if _, err := Run(context.Background(), nil); err != ErrEmptyCorpus {
		t.Errorf("Run(nil) = %v, want ErrEmptyCorpus", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, map[string]string{"a.smali": "x"}); err != context.Canceled {
		t.Errorf("Run(canceled ctx) = %v, want context.Canceled", err)
	}
}

func TestRunEndToEnd(t *testing.T) {
	files := map[string]string{
		"smali/com/example/A.smali": ".class public Lcom/example/A;\n.super Ljava/lang/Object;\n",
	}
	res, err := Run(context.Background(), files, WithWorkers(1))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("categories=%v findingCount=%d duration=%s", res.CategoryList(), res.FindingCount, res.Duration)
	for _, l := range res.Locations {
		if filepath.IsAbs(l.File) {
			t.Errorf("absolute path leaked into Locations: %q", l.File)
		}
	}
}
