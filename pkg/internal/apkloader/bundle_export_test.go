package apkloader

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportBundleHermes96IsNotFakeJavaScript(t *testing.T) {
	input := filepath.Join(t.TempDir(), "index.android.bundle")
	data := buildTestHBC(t, 96, []string{"main", "moduleA", "https://example.com/api"})
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	coverage, err := ExportBundle(context.Background(), input, out)
	if err != nil || coverage.Version != 96 || coverage.Status != "complete" {
		t.Fatalf("coverage=%+v error=%v", coverage, err)
	}
	disasm, err := os.ReadFile(filepath.Join(out, "hermes.disasm.txt"))
	if err != nil || !strings.Contains(string(disasm), "LoadConstString") || !strings.Contains(string(disasm), "https://example.com/api") {
		t.Fatalf("missing readable bytecode: %s %v", disasm, err)
	}
	if _, err := os.Stat(filepath.Join(out, "deobfuscated.js")); !os.IsNotExist(err) {
		t.Fatal("Hermes must not be emitted as JS")
	}
	original, err := os.ReadFile(filepath.Join(out, "original.bundle"))
	if err != nil || !bytes.Equal(original, data) {
		t.Fatal("original was lost or modified")
	}
}

func TestExportBundleTextJSAndBinary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		data   []byte
		status string
		js     bool
	}{
		{"plain.js", []byte(`const endpoint = "\x68\x74\x74\x70\x73://example.com";`), "complete", true},
		{"game.bundle", []byte("UnityFS\x00binary data"), "unsupported", false},
		{"bad.hbc", HermesMagicLE, "failed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), tc.name)
			os.WriteFile(input, tc.data, 0600)
			out := t.TempDir()
			coverage, err := ExportBundle(context.Background(), input, out)
			if err != nil || coverage.Status != tc.status {
				t.Fatalf("%+v %v", coverage, err)
			}
			_, err = os.Stat(filepath.Join(out, "original.js"))
			if (err == nil) != tc.js {
				t.Fatalf("unexpected JS output: %v", err)
			}
			if tc.js {
				original, readErr := os.ReadFile(filepath.Join(out, "original.js"))
				if readErr != nil || !bytes.Equal(original, tc.data) {
					t.Fatal("JS source changed", readErr)
				}
				decoded, readErr := os.ReadFile(filepath.Join(out, "decoded_strings.json"))
				if readErr != nil || !bytes.Contains(decoded, []byte("https://example.com")) {
					t.Fatal("decoded strings missing", readErr)
				}
			}
			if _, err = os.Stat(filepath.Join(out, "coverage.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExportBundleUnknownVersionAndCancellation(t *testing.T) {
	data := buildTestHBC(t, 96, []string{"main", "moduleA", "url"})
	binary.LittleEndian.PutUint32(data[8:12], 999)
	input := filepath.Join(t.TempDir(), "v999.hbc")
	os.WriteFile(input, data, 0600)
	coverage, err := ExportBundle(context.Background(), input, t.TempDir())
	if err != nil || coverage.Status != "unsupported" || len(coverage.Diagnostics) == 0 {
		t.Fatalf("%+v %v", coverage, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	coverage, err = ExportBundle(ctx, input, t.TempDir())
	if err == nil || coverage.Status != "partial" {
		t.Fatal("cancellation must be visible")
	}
}
