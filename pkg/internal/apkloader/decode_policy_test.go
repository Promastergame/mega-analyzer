package apkloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestDecodeRetiredBackendDoesNotFallback(t *testing.T) {
	t.Setenv("MEGA_STANDALONE", "")
	dir := testutil.TempDir(t)
	dex, _, err := AssembleSmaliText("Hello.smali", nativeHelloSmali, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "input.dex")
	if err := os.WriteFile(input, dex, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	_, err = NewExtractor().DecodeDEX(t.Context(), input, DecodeOptions{
		OutputDir: out, DexBackend: "baksmali",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown decode backend") {
		t.Fatalf("explicit backend error was lost: %v", err)
	}
	if hasSmaliFiles(out) {
		t.Fatal("a retired backend silently used the native backend")
	}
	if _, err := os.Stat(filepath.Join(out, decodeCacheFile)); !os.IsNotExist(err) {
		t.Fatalf("failed decode wrote success metadata: %v", err)
	}
}

func TestLegacySmaliWriterPreservesCaseCollisions(t *testing.T) {
	p := &DEXParser{classes: []*ClassDef{{ClassName: "La/A;"}, {ClassName: "La/a;"}}}
	dir := testutil.TempDir(t)
	if err := NewExtractor().generateSmaliInto(p, dir, 2); err != nil {
		t.Fatal(err)
	}
	var paths []string
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".smali" {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("legacy entry point lost a class: %v", paths)
	}
}
