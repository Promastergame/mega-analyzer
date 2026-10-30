package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
)

func TestHandleDecodeUsesSharedDEXService(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("MEGA_STANDALONE", "")
	dex, _, err := apkloader.AssembleSmaliText("Value.smali", `.class public Lexample/Value;
.super Ljava/lang/Object;
.method public static value()I
    .registers 1
    const/4 v0, 7
    return v0
.end method
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "value.dex")
	if err := os.WriteFile(input, dex, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, noHeaders := range []bool{false, true} {
		var output bytes.Buffer
		out := filepath.Join(dir, "with-headers")
		if noHeaders {
			out = filepath.Join(dir, "without-headers")
		}
		app := &App{
			opts: &CLIOptions{
				Target: input, Output: out, DexBackend: "native", Standalone: true,
				SmaliHeaders: true, NoSmaliHeaders: noHeaders,
			},
			output: NewOutputWithWriter(NoColorTheme(), false, &output),
		}
		if err := app.handleDecode(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(out, "smali/example/Value.smali"))
		if err != nil || bytes.HasPrefix(data, []byte("# Disassembled")) == noHeaders {
			t.Fatalf("header options were not passed through: noHeaders=%t err=%v data=%s", noHeaders, err, data)
		}
		if !strings.Contains(output.String(), "1 smali files") || !strings.Contains(output.String(), "Backend: native") {
			t.Fatalf("missing shared decode result: %s", output.String())
		}
	}
	if apkloader.Standalone() {
		t.Fatal("analyzer decode changed the process-wide standalone policy")
	}
}

func TestHandleDecodeRejectsInvalidBackendBeforeCreatingOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(input, []byte("PK\x03\x04"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	out := filepath.Join(dir, "out")
	app := &App{
		opts:   &CLIOptions{Target: input, Output: out, DexBackend: "baksmali", Standalone: true},
		output: NewOutputWithWriter(NoColorTheme(), false, &output),
	}
	if err := app.handleDecode(); err == nil {
		t.Fatal("standalone decode must reject the external backend")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("invalid options created output: %v", err)
	}
}
