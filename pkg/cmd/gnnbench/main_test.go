package main

import (
	"archive/zip"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/testutil"
)

func runForTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	oldFlags, oldArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	flag.CommandLine = flag.NewFlagSet("gnnbench-test", flag.ContinueOnError)
	os.Args = append([]string{"gnnbench"}, args...)
	var err error
	out := testutil.CaptureStdout(t, func() { err = run() })
	return out, err
}

func TestArgumentAndInputErrors(t *testing.T) {
	root := testutil.TempDir(t)
	// Failed decode still creates its explicit output directory: contain all
	// artifacts under a test-owned temporary root on Unix and Windows.
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, root)
	}
	missing := filepath.Join(root, "missing.apk")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{nil, "-apk is required"}, {[]string{"-apk", missing, "-mode", "wrong"}, "unknown mode"},
		{[]string{"-apk", missing}, "prepare input"}, {[]string{"-apk", missing, "-mode", "decode"}, "decode apk"},
	} {
		_, err := runForTest(t, tt.args...)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("args=%v err=%v want %s", tt.args, err, tt.want)
		}
	}
}

func TestDirectBenchmarkBuildsGraphs(t *testing.T) {
	dir := testutil.TempDir(t)
	source := `.class public Lfixture/Main;
.super Ljava/lang/Object;
.method public static compute(I)I
 .registers 4
 const-string v1, "session"
 const/4 v2, 0x1
 invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
 if-eqz p0, :zero
 const/4 v0, 0x1
 goto :done
 :zero
 const/4 v0, 0x0
 :done
 return v0
.end method
`
	if err := os.WriteFile(filepath.Join(dir, "Main.smali"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runForTest(t, "-apk", dir, "-mode", "direct")
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"RESULT mode=direct", "files_analyzed:", "graphs_built:", "nodes/edges:"} {
		if !strings.Contains(out, part) {
			t.Errorf("missing %q in output %s", part, out)
		}
	}
	if strings.Contains(out, "graphs_built:    0") {
		t.Fatalf("synthetic branches did not build a graph: %s", out)
	}
}

func TestDecodeBenchmark(t *testing.T) {
	apk := filepath.Join(testutil.TempDir(t), "fixture.apk")
	f, err := os.Create(apk)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, err := z.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(axml.MinimalManifestXML()); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := runForTest(t, "-apk", apk, "-mode", "decode")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "RESULT mode=decode") {
		t.Fatal(out)
	}
}

func TestDedupPercentage(t *testing.T) {
	for _, tt := range []struct {
		total, unique int64
		want          float64
	}{{0, 0, 0}, {10, 10, 0}, {10, 0, 100}, {4, 1, 75}} {
		if got := dedupPct(tt.total, tt.unique); got != tt.want {
			t.Errorf("dedup(%d,%d)=%v", tt.total, tt.unique, got)
		}
	}
}
