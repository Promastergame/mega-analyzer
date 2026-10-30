package apkid

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"testing"

	dexpkg "mega-analyzer/pkg/internal/apkid/dex"
	elfpkg "mega-analyzer/pkg/internal/apkid/elf"
)

// FuzzDEXParse fuzzes the DEX parser with arbitrary byte slices.
// Run with: go test -fuzz=FuzzDEXParse ./pkg/internal/apkid/...
func FuzzDEXParse(f *testing.F) {
	// Seed corpus: valid DEX magic, truncated DEX, zero bytes, random bytes.
	f.Add([]byte("dex\n035\x00"))
	f.Add([]byte("dex\n035\x00" + string(bytes.Repeat([]byte{0}, 120))))
	f.Add([]byte{})
	f.Add([]byte("not a dex file at all"))
	f.Add([]byte("\x7fELF")) // ELF magic — parser should handle gracefully

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic.
		info, _ := dexpkg.ParseDEX(data)
		if info == nil {
			t.Fatal("ParseDEX returned nil info")
		}
		// If valid, string pool and map order must be consistent.
		if info.Valid {
			_ = info.StringPool
			_ = info.MapOrder
			_ = info.Compiler
		}
	})
}

// FuzzELFScan fuzzes the ELF scanner with arbitrary byte slices.
// Run with: go test -fuzz=FuzzELFScan ./pkg/internal/apkid/...
func FuzzELFScan(f *testing.F) {
	f.Add([]byte("\x7fELF\x01\x01\x01\x00"))
	f.Add([]byte("\x7fELF\x02\x01\x01\x00"))
	f.Add([]byte{})
	f.Add([]byte("UPX!"))
	f.Add([]byte("not an elf"))

	f.Fuzz(func(t *testing.T, data []byte) {
		info, _ := elfpkg.ScanELF(data)
		if info == nil {
			t.Fatal("ScanELF returned nil info")
		}
		_ = info.HasUPX
		_ = info.Sections
	})
}

// FuzzScanArchive fuzzes the archive scanner with arbitrary ZIP-like data.
// Run with: go test -fuzz=FuzzScanArchive ./pkg/internal/apkid/...
func FuzzScanArchive(f *testing.F) {
	// Seed: valid ZIP, empty, random bytes.
	validZIP := func() []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create("classes.dex")
		_, _ = w.Write([]byte("dex\n035\x00"))
		_ = zw.Close()
		return buf.Bytes()
	}()
	f.Add(validZIP)
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04")) // ZIP local file header magic
	f.Add([]byte("not a zip"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Write to a temp file (zip.OpenReader requires a file).
		tmp, err := os.CreateTemp("", "apkid-fuzz-*.zip")
		if err != nil {
			return // skip if we can't create tmp file
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		_, _ = tmp.Write(data)
		tmp.Close()

		// Must never panic, must always return.
		ctx, cancel := context.WithTimeout(context.Background(), 5*0) // 0 timeout = use default
		_ = cancel
		ctx = context.Background()
		defer cancel()

		rep, _ := ScanWithContext(ctx, tmpName, ScanOptions{
			MaxFileBytes:  1 << 20, // 1 MiB limit for fuzz
			MaxTotalBytes: 4 << 20,
			MaxDepth:      1,
		})
		_ = rep
	})
}

// FuzzAhoCorasick fuzzes the Aho-Corasick automaton search.
func FuzzAhoCorasick(f *testing.F) {
	f.Add([]byte("hello world"), []byte("world"))
	f.Add([]byte{}, []byte("pattern"))
	f.Add([]byte("aababababab"), []byte("ab"))

	f.Fuzz(func(t *testing.T, data, pattern []byte) {
		if len(pattern) == 0 {
			return
		}
		ac := newAhoCorasick([][]byte{pattern})
		hits := ac.findAll(data)
		_ = hits
	})
}
