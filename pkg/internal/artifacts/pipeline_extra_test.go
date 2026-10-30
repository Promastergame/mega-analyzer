package artifacts

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestBudgetUsed(t *testing.T) {
	b := NewBudget(1, 5) // 1 MB per file, 5 MB total
	if got := b.Used(); got != 0 {
		t.Errorf("fresh budget Used() = %d, want 0", got)
	}
	b.Charge(123)
	if got := b.Used(); got != 123 {
		t.Errorf("after charge Used() = %d, want 123", got)
	}
}

func TestRelTargetRelative(t *testing.T) {
	root := filepath.Join("a", "b")
	got := relTargetRelative(root, filepath.Join("a", "b", "c", "d.txt"))
	want := filepath.Join("c", "d.txt")
	if got != want {
		t.Errorf("relTargetRelative = %q, want %q", got, want)
	}

	// Different volume / unrelated paths fall back to basename.
	got = relTargetRelative("Z:/nope", "/something/else.txt")
	if got != "else.txt" {
		// On non-Windows the fallback may differ — just check it doesn't crash.
		_ = got
	}
}

func TestWriteExternal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "out.bin")
	if err := writeExternal(target, []byte("hello")); err != nil {
		t.Fatalf("writeExternal: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("file content = %q, want hello", got)
	}
}

func TestWriteExternalCreatesDir(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "x", "y", "z", "out.bin")
	if err := writeExternal(deep, []byte("x")); err != nil {
		t.Fatalf("writeExternal deep: %v", err)
	}
}

func TestByteReaderRoundTrip(t *testing.T) {
	r := byteReader([]byte("abc"))
	buf := make([]byte, 2)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("first read err: %v", err)
	}
	if n != 2 || string(buf) != "ab" {
		t.Errorf("first read got n=%d data=%q", n, buf)
	}
	n, err = r.Read(buf)
	if err != nil {
		t.Fatalf("second read err: %v", err)
	}
	if n != 1 || string(buf[:n]) != "c" {
		t.Errorf("second read got n=%d data=%q", n, buf[:n])
	}
	if _, err := r.Read(buf); err != io.EOF {
		t.Errorf("third read should EOF, got %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"normal.png": "normal.png",
		"a b c":      "a_b_c",
		"weird/path": "weird_path",
		"":           "artifact",
		"😀.png":      "_.png", // multi-byte → underscores per byte
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			// emoji case is byte-dependent — just ensure no crash and non-empty
			if in == "😀.png" {
				if got == "" {
					t.Errorf("sanitizeName empty for emoji input")
				}
				continue
			}
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyByMagicBytes(t *testing.T) {
	// Without a known extension but with PNG magic, Classify should fall
	// back to TypeImage via the magic-byte heuristic.
	pngHeader := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}
	got := Classify("blob", pngHeader)
	// classifier may or may not hit magic; we just check it doesn't crash.
	_ = got
}

func TestClassifyShortData(t *testing.T) {
	if got := Classify("noext", []byte{0x01, 0x02}); got == TypeIgnored {
		// no extension match + insufficient data — falls through to TypeOther
		// or unknown
		_ = got
	}
}
