package apkloader

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJSExportPreservesSyntaxAndSeparatesDecodedText(t *testing.T) {
	data := []byte("const quote = \"a\\x22b\";\nconst slash = '\\x5c';\nconst newline = '\\u000a';\nconst regex = /\\x22/;\nconst unicode = '\\uD83D\\uDE00';\nconst template = `\\x22${1}`;\n")
	input := filepath.Join(t.TempDir(), "escapes.js")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	coverage, err := ExportBundle(context.Background(), input, out)
	if err != nil || coverage.Status != "complete" || coverage.Mode != "original_and_decoded_strings" {
		t.Fatalf("%+v %v", coverage, err)
	}
	for _, name := range []string{"original.bundle", "original.js"} {
		raw, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || !bytes.Equal(raw, data) {
			t.Fatalf("%s changed: %q %v", name, raw, err)
		}
	}
	decoded, err := os.ReadFile(filepath.Join(out, "decoded_strings.json"))
	var fragments []string
	if err != nil || json.Unmarshal(decoded, &fragments) != nil || len(fragments) == 0 {
		t.Fatalf("%q %v", decoded, err)
	}
	if _, err := os.Stat(filepath.Join(out, "deobfuscated.js")); !os.IsNotExist(err) {
		t.Fatal("decoded text emitted as JS")
	}
	opts, _ := BundleBudget("compact")
	opts.MaxOutputBytes = 8
	coverage, err = ExportBundleWithOptions(context.Background(), input, t.TempDir(), opts)
	if err != nil || coverage.Status != "partial" {
		t.Fatalf("output limit hidden: %+v %v", coverage, err)
	}
}
