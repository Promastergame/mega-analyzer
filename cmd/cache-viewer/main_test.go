package main

import (
	"encoding/binary"
	"flag"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cacheFrame(kind byte, key, value string) []byte {
	frame := make([]byte, 13)
	frame[0] = kind
	binary.LittleEndian.PutUint32(frame[1:5], uint32(len(key)))
	binary.LittleEndian.PutUint64(frame[5:13], uint64(len(value)))
	frame = append(frame, key...)
	frame = append(frame, value...)
	checksum := crc32.ChecksumIEEE([]byte(key + value))
	return binary.LittleEndian.AppendUint32(frame, checksum)
}

func writeCacheFixture(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.db")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCacheReplaysUpdatesDeletesAndCorruption(t *testing.T) {
	const keyA = "dex-a\x00emitter\x00Lsample/A;"
	const keyB = "dex-b\x00emitter\x00Lsample/B;"
	data := []byte(magic)
	for _, frame := range [][]byte{
		cacheFrame(1, keyA, "old"), cacheFrame(1, keyB, "removed"),
		cacheFrame(1, keyA, ".class Lsample/A;"), cacheFrame(2, keyB, ""),
		cacheFrame(1, "malformed-key", "ignored"),
	} {
		data = append(data, frame...)
	}
	bad := cacheFrame(1, keyA, "bad checksum must not replace the valid record")
	bad[len(bad)-1] ^= 0xff
	data = append(data, bad...)
	rows, err := load(writeCacheFixture(t, data))
	if err != nil || len(rows) != 1 {
		t.Fatalf("load = %+v, %v", rows, err)
	}
	r := rows[0]
	if r.Key != keyA || r.Dex != "dex-a" || r.Emitter != "emitter" || r.Class != "Lsample/A;" || r.Smali != ".class Lsample/A;" || r.Size != int64(len(r.Smali)) {
		t.Fatalf("record replay: %+v", r)
	}
}

func TestLoadCachePreservesCompletePrefixAfterTruncatedAppend(t *testing.T) {
	const keyA = "dex\x00emitter\x00A"
	prefix := append([]byte(magic), cacheFrame(1, keyA, "complete")...)
	last := cacheFrame(1, "dex\x00emitter\x00B", "incomplete")
	for _, length := range []int{1, 5, 13, 15, len(last) - 5, len(last) - 1} {
		data := append(append([]byte{}, prefix...), last[:length]...)
		rows, err := load(writeCacheFixture(t, data))
		if err != nil || len(rows) != 1 || rows[0].Key != keyA || rows[0].Smali != "complete" {
			t.Fatalf("truncated at %d: %+v %v", length, rows, err)
		}
	}
	for _, data := range [][]byte{nil, []byte("short"), []byte("NOTCACHE")} {
		if _, err := load(writeCacheFixture(t, data)); err == nil {
			t.Fatalf("accepted invalid header %q", data)
		}
	}
	if _, err := load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	rows, err := load(writeCacheFixture(t, []byte(magic)))
	if err != nil || len(rows) != 0 {
		t.Fatalf("empty cache: %+v %v", rows, err)
	}
}

func runCacheViewer(t *testing.T, args ...string) string {
	t.Helper()
	previousArgs, previousFlags, previousStdout := os.Args, flag.CommandLine, os.Stdout
	defer func() { os.Args, flag.CommandLine, os.Stdout = previousArgs, previousFlags, previousStdout }()
	output, err := os.Create(filepath.Join(t.TempDir(), "stdout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	os.Args = append([]string{"cache-viewer"}, args...)
	flag.CommandLine = flag.NewFlagSet("cache-viewer", flag.ContinueOnError)
	os.Stdout = output
	main()
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCacheViewerCLIListsFiltersLimitsAndDumps(t *testing.T) {
	data := append([]byte(magic), cacheFrame(1, "dex-z\x00engine\x00Lsample/Zeta;", ".class Lsample/Zeta;")...)
	data = append(data, cacheFrame(1, "dex-a\x00engine\x00Lsample/Alpha;", ".class Lsample/Alpha;")...)
	path := writeCacheFixture(t, data)
	all := runCacheViewer(t, "-limit", "0", path)
	if !strings.Contains(all, "2 shown / 2 matched / 2 total") || strings.Index(all, "Lsample/Alpha;") > strings.Index(all, "Lsample/Zeta;") {
		t.Fatalf("unsorted/incomplete output: %s", all)
	}
	limited := runCacheViewer(t, "-limit", "1", path)
	if !strings.Contains(limited, "1 shown / 2 matched / 2 total") || strings.Contains(limited, "Lsample/Zeta;") {
		t.Fatalf("limit ignored: %s", limited)
	}
	filtered := runCacheViewer(t, "-find", "ALPHA", path)
	if !strings.Contains(filtered, "1 shown / 1 matched / 2 total") || !strings.Contains(filtered, "Lsample/Alpha;") || strings.Contains(filtered, "Lsample/Zeta;") {
		t.Fatalf("filter ignored: %s", filtered)
	}
	if got := runCacheViewer(t, "-dump", "Lsample/Zeta;", path); got != ".class Lsample/Zeta;" {
		t.Fatalf("dump changed source: %q", got)
	}
}
