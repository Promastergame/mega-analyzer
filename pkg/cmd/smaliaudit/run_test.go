package smaliaudit

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mega-analyzer/pkg/ml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const simpleSmali = `.class public Lapp/Test;
.super Ljava/lang/Object;
.method public static run(Landroid/content/Intent;)V
 .locals 2
 invoke-virtual {p0,v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
 move-result-object v0
 invoke-virtual {v1,v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
 return-void
.end method
`

func writeSample(t *testing.T) string {
	t.Helper()
	p := filepath.Join(testTempDir(t), "Test.smali")
	if err := os.WriteFile(p, []byte(simpleSmali), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func testTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "smaliaudit-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var lastErr error
		for attempt := 0; attempt < 5; attempt++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			} else {
				lastErr = err
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("cleanup temp dir: %v", lastErr)
	})
	return dir
}
func TestAuditCLIEndToEndAndReadOnly(t *testing.T) {
	input := writeSample(t)
	dir := testTempDir(t)
	output := filepath.Join(dir, "audit.json")
	sarif := filepath.Join(dir, "audit.sarif")
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"-input", input, "-json", output, "-sarif", sarif}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", code, &stderr, &stdout)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Audit.Coverage.StaticFlows != 1 || report.SHA256 == "" {
		t.Fatalf("bad report: %+v", report)
	}
	original, err := os.ReadFile(input)
	if err != nil || string(original) != simpleSmali {
		t.Fatal("input was modified")
	}
	sarifBytes, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(sarifBytes, &document); err != nil {
		t.Fatal(err)
	}
	if document["version"] != "2.1.0" {
		t.Fatal("wrong SARIF version")
	}
	runs := document["runs"].([]any)
	run := runs[0].(map[string]any)
	foundFlow := false
	for _, v := range run["results"].([]any) {
		r := v.(map[string]any)
		if r["properties"].(map[string]any)["evidenceLevel"] == "static_flow" {
			foundFlow = true
			if r["codeFlows"] == nil {
				t.Fatal("missing codeFlows")
			}
		}
	}
	if !foundFlow {
		t.Fatal("no SARIF static flow")
	}
}
func TestAuditCLIRejectsOverwritingInput(t *testing.T) {
	input := writeSample(t)
	var out bytes.Buffer
	if Main(context.Background(), []string{"-input", input, "-json", input}, &out, &out) != 1 {
		t.Fatal("allowed overwrite")
	}
	raw, _ := os.ReadFile(input)
	if string(raw) != simpleSmali {
		t.Fatal("input changed")
	}
}
func TestAuditCLIRejectsOutputInsideSmaliDirectory(t *testing.T) {
	input := writeSample(t)
	var out bytes.Buffer
	if Main(context.Background(), []string{"-input", filepath.Dir(input), "-json", filepath.Join(filepath.Dir(input), "report.json")}, &out, &out) != 1 {
		t.Fatal("allowed write into input tree")
	}
}
func TestAuditCommandHandlesMalformedAPKWithoutExtracting(t *testing.T) {
	root := testTempDir(t)
	input := filepath.Join(root, "bad.apk")
	file, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range []struct{ name, body string }{{"../../outside.txt", "not extracted"}, {"AndroidManifest.xml", `<manifest package="app.test" xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35"/><application android:debuggable="false"/></manifest>`}, {"classes.dex", "not a DEX"}} {
		w, e := writer.Create(entry.name)
		if e != nil {
			t.Fatal(e)
		}
		w.Write([]byte(entry.body))
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	report, err := Run(context.Background(), Options{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if report.Audit.AnalysisComplete || len(report.Audit.Diagnostics) == 0 {
		t.Fatal("malformed APK reported complete")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("APK members extracted unexpectedly")
	}
}
func TestAuditReadBudgetsAndPaths(t *testing.T) {
	if _, err := readBounded(strings.NewReader("1234"), 3); err == nil {
		t.Fatal("read budget ignored")
	}
	for _, s := range []string{"/absolute", "../escape", "a/../../escape", "a\\b", "C:/x", "a\x00b"} {
		if safeMemberPath(s) {
			t.Errorf("unsafe path accepted: %q", s)
		}
	}
	if !safeMemberPath("lib/arm64-v8a/libtest.so") {
		t.Fatal("valid path rejected")
	}
}
func TestAuditCommandDirectorySymlinkIsSkipped(t *testing.T) {
	root := testTempDir(t)
	if err := os.WriteFile(filepath.Join(root, "A.smali"), []byte(simpleSmali), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "A.smali"), filepath.Join(root, "Alias.smali")); err != nil {
		t.Skip(err)
	}
	r, err := Run(context.Background(), Options{Input: root})
	if err != nil {
		t.Fatal(err)
	}
	if r.Audit.AnalysisComplete || r.Audit.Coverage.FilesParsed != 1 {
		t.Fatal("symlink not explicitly skipped")
	}
}
func TestAuditCLIIncompleteExitCode(t *testing.T) {
	input := writeSample(t)
	var out bytes.Buffer
	code := Main(context.Background(), []string{"-input", input, "-json", filepath.Join(testTempDir(t), "r.json"), "-max-findings", "1"}, &out, &out)
	if code != 2 {
		t.Fatalf("exit=%d want 2; %s", code, &out)
	}
}
func TestAuditCLIHelp(t *testing.T) {
	var out bytes.Buffer
	if code := Main(context.Background(), []string{"-h"}, &out, &out); code != 0 {
		t.Fatal(code)
	}
}
func TestAuditWriteJSONFailureLeavesOldFile(t *testing.T) {
	file := filepath.Join(testTempDir(t), "r.json")
	os.WriteFile(file, []byte("original"), 0600)
	if err := WriteJSON(file, make(chan int)); err == nil {
		t.Fatal("expected encoding error")
	}
	raw, _ := os.ReadFile(file)
	if string(raw) != "original" {
		t.Fatal("partial write overwrote report")
	}
}
func TestAuditConfigFlowOnlyThroughCommand(t *testing.T) {
	r, err := Run(context.Background(), Options{Input: writeSample(t), Config: ml.SmaliAuditConfig{NoHeuristics: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Audit.Findings) != 1 || r.Audit.Findings[0].EvidenceLevel != "static_flow" {
		t.Fatal("flow-only ignored")
	}
}

func TestAuditReportParentSymlinkCannotWriteIntoInput(t *testing.T) {
	root := testTempDir(t)
	input := filepath.Join(root, "input")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "Flow.smali"), []byte(simpleSmali), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(input, alias); err != nil {
		t.Skip(err)
	}
	output := filepath.Join(alias, "nested", "report.json")
	if err := validateOutputPaths(input, output); err == nil {
		t.Fatal("report via symlink allowed inside input")
	}
	if _, err := os.Stat(filepath.Join(input, "nested")); !os.IsNotExist(err) {
		t.Fatal("validation modified input")
	}
}
func TestAuditReportDestinationsCannotAliasViaParentSymlink(t *testing.T) {
	root := testTempDir(t)
	input := filepath.Join(root, "Flow.smali")
	if err := os.WriteFile(input, []byte(simpleSmali), 0600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(root, "reports")
	if err := os.Mkdir(outputDir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(outputDir, alias); err != nil {
		t.Skip(err)
	}
	if err := validateOutputPaths(input, filepath.Join(outputDir, "out.json"), filepath.Join(alias, "out.json")); err == nil {
		t.Fatal("two aliased destinations accepted")
	}
}
