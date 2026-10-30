package binzap

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRunnerAndExtractor(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test smali file
	smaliPath := filepath.Join(tmpDir, "app.smali")
	content := `.class public LApp;
.super Ljava/lang/Object;
.method public static foo()V
    .registers 1
    const-string v0, "isDebuggerConnected"
    return-void
.end method
`
	if err := os.WriteFile(smaliPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create subfolder with asm file
	subDir := filepath.Join(tmpDir, "native")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	asmPath := filepath.Join(subDir, "lib.s")
	if err := os.WriteFile(asmPath, []byte("mov eax, ebx\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create non-supported file
	txtPath := filepath.Join(tmpDir, "notes.txt")
	if err := os.WriteFile(txtPath, []byte("ignore me"), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Test collectFiles
	files, err := collectFiles(tmpDir)
	if err != nil {
		t.Fatalf("collectFiles: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 supported files (.smali and .s), got %v", files)
	}

	// 2. Test scanOneFile (passive and active)
	findings, err := scanOneFile(smaliPath, true)
	if err != nil {
		t.Fatalf("scanOneFile: %v", err)
	}
	_ = findings

	// 3. Test RunPassiveFile
	pFindings, err := RunPassiveFile(smaliPath)
	if err != nil {
		t.Fatalf("RunPassiveFile: %v", err)
	}
	_ = pFindings

	// 4. Test RunPassiveDirectory
	dirFindings, err := RunPassiveDirectory(tmpDir)
	if err != nil {
		t.Fatalf("RunPassiveDirectory: %v", err)
	}
	_ = dirFindings

	// 5. Test RunScanDirectory with options
	var progressCalled atomic.Bool
	opts := ScanOptions{
		Workers:  2,
		Active:   true,
		Progress: func(done, total int) { progressCalled.Store(true) },
		Baseline: NewBaseline(),
	}
	scanFindings, err := RunScanDirectory(context.Background(), tmpDir, opts)
	if err != nil {
		t.Fatalf("RunScanDirectory: %v", err)
	}
	if !progressCalled.Load() {
		t.Error("expected progress callback to be invoked")
	}

	// 6. Test GenerateFullReport
	outDir := filepath.Join(tmpDir, "reports")
	if err := GenerateFullReport(scanFindings, outDir, "test"); err != nil {
		t.Errorf("GenerateFullReport: %v", err)
	}

	// 7. Test UnpackAPK with non-existent file
	ctx := context.Background()
	_, _ = UnpackAPK(ctx, filepath.Join(tmpDir, "missing.apk"))
}
