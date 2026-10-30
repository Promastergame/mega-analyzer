package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleBinzapRunsInProcess(t *testing.T) {
	dir := t.TempDir()
	smali := filepath.Join(dir, "Example.smali")
	if err := os.WriteFile(smali, []byte(".class public LExample;\n.method public test()V\n\tinvoke-virtual {p0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)V\n.end method\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	app := NewApp()
	app.opts = &CLIOptions{Output: filepath.Join(dir, "reports"), Workers: 1}
	app.output = NewOutputWithWriter(DarkTheme(), true, &bytes.Buffer{})
	if err := app.handleBinzap(smali); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "reports", "bytecode", "Example_binzap_report.md")); err != nil {
		t.Fatalf("BinZAP report was not generated: %v", err)
	}
}

func TestCLIUsesFormatNamesInsteadOfBackendNames(t *testing.T) {
	bytecode, err := NewCLIParser().Parse([]string{"--scan-bytecode", "-t", "app.apk"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytecode.Binzap {
		t.Fatal("--scan-bytecode did not select the bytecode backend")
	}

	deep, err := NewCLIParser().Parse([]string{"--scan-bytecode-deep", "-t", "decoded"})
	if err != nil {
		t.Fatal(err)
	}
	if err := deep.Validate(); err != nil {
		t.Fatal(err)
	}
	if !deep.Binzap || !deep.BinzapActive {
		t.Fatal("--scan-bytecode-deep did not enable deep bytecode analysis")
	}

	native, err := NewCLIParser().Parse([]string{"--scan-native", "-t", "app.exe"})
	if err != nil {
		t.Fatal(err)
	}
	if !native.MachineCode {
		t.Fatal("--scan-native did not select native analysis")
	}
}
