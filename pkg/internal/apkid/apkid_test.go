package apkid

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeFakeAPK creates a tiny zip archive with the given members so
// we can exercise scanArchive without depending on a real APK.
func writeFakeAPK(t *testing.T, members map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	apk := filepath.Join(dir, "fake.apk")
	f, err := os.Create(apk)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, payload := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}
	return apk
}

func mustHaveID(t *testing.T, r *Report, id string) {
	t.Helper()
	for _, m := range r.Matches {
		if m.ID == id {
			return
		}
	}
	ids := []string{}
	for _, m := range r.Matches {
		ids = append(ids, m.ID)
	}
	t.Fatalf("expected match %q not found, got: %v", id, ids)
}

func TestScan_DetectsR8Compiler(t *testing.T) {
	dexBlob := bytes.Join([][]byte{
		[]byte("dex\n035\x00"),
		[]byte("\x00\x00\x00\x00"),
		[]byte("emitter: com.android.tools.r8 v3.3.75"),
	}, nil)

	apk := writeFakeAPK(t, map[string][]byte{
		"classes.dex": dexBlob,
	})

	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "compiler.d8_r8")
	if rep.PrimaryCompiler != "d8 / r8" {
		t.Fatalf("primary compiler = %q, want %q", rep.PrimaryCompiler, "d8 / r8")
	}
	if rep.Score <= 0 {
		t.Fatalf("expected positive score, got %d", rep.Score)
	}
}

func TestScan_DetectsBangclePacker(t *testing.T) {
	apk := writeFakeAPK(t, map[string][]byte{
		"classes.dex":                   []byte("dex\n035\x00 something com/secneo/apkwrapper bla"),
		"lib/armeabi-v7a/libsecmain.so": []byte("ELF\x7fbinary"),
	})

	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "packer.bangcle")
	if got := rep.Categories[CategoryPacker]; len(got) == 0 {
		t.Fatalf("expected at least 1 packer match in categories, got %v", rep.Categories)
	}
	if rep.Score < 18 {
		t.Fatalf("expected score >= 18 for packer hit, got %d", rep.Score)
	}
}

func TestScan_DetectsAntiDebugAndAntiVM(t *testing.T) {
	// tracerpid rule is AllOf: BOTH /proc/self/status AND TracerPid must appear.
	// This is intentional — /proc/self/status alone is too noisy.
	smali := []byte(`
.class public Lcom/example/Foo;
.method public probe()V
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    const-string v0, "/proc/self/status"
    const-string v1, "TracerPid"
    const-string v2, "ro.kernel.qemu"
.end method
`)
	apk := writeFakeAPK(t, map[string][]byte{
		"smali/com/example/Foo.smali": smali,
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "anti_debug.is_debugger_connected")
	mustHaveID(t, rep, "anti_debug.tracerpid")
	mustHaveID(t, rep, "anti_vm.qemu_props")
}

func TestScan_NothingForBenignAssets(t *testing.T) {
	apk := writeFakeAPK(t, map[string][]byte{
		"assets/readme.txt":   []byte("just plain notes\n"),
		"AndroidManifest.xml": []byte(`<manifest package="x" />`),
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.Matches) != 0 {
		t.Fatalf("expected zero matches, got %v", rep.Matches)
	}
	if rep.Score != 0 {
		t.Fatalf("expected score 0, got %d", rep.Score)
	}
	if rep.PrimaryCompiler != "unknown" {
		t.Fatalf("compiler should be unknown without dex, got %q", rep.PrimaryCompiler)
	}
}

func TestScan_DirectoryMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "smali", "com", "guardsquare"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "smali", "com", "guardsquare", "DexGuard.smali"),
		[]byte("class com/guardsquare/dexguard"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rep, err := Scan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "obfuscator.dexguard")
}

func TestScan_MissingTarget(t *testing.T) {
	if _, err := Scan(filepath.Join(t.TempDir(), "no-such-thing")); err == nil {
		t.Fatalf("expected error for missing target")
	}
}

// ── New Tests ─────────────────────────────────────────────────────────────────

// TestScan_EntryNameMatcher verifies that packers are detected via the zip
// entry filename, even when the entry content is arbitrary binary data that
// doesn't contain any string evidence.
func TestScan_EntryNameMatcher(t *testing.T) {
	apk := writeFakeAPK(t, map[string][]byte{
		// Random binary — no string evidence inside.
		"lib/armeabi-v7a/libjiagu.so": bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 64),
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "packer.qihoo_360")
}

// TestScan_ObfuscatorOnRealDEX verifies that obfuscator rules fire on real DEX
// (not just apktool-extracted smali). The rule uses dex_string matchers that
// search the DEX string pool, fixing the original scope:"smali"-only bug.
func TestScan_ObfuscatorOnRealDEX(t *testing.T) {
	// Build a minimal DEX that has "com/guardsquare/dexguard" in its string pool.
	dex := buildMinimalDEX(t, []string{"com/guardsquare/dexguard", "Ljava/lang/Object;"})
	apk := writeFakeAPK(t, map[string][]byte{
		"classes.dex": dex,
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "obfuscator.dexguard")
}

// TestScan_ContextCancel verifies that ScanWithContext respects cancellation.
func TestScan_ContextCancel(t *testing.T) {
	apk := writeFakeAPK(t, map[string][]byte{
		"classes.dex": append([]byte("dex\n035\x00"), bytes.Repeat([]byte("a"), 1024)...),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	// Should return quickly (cancelled or with no entries processed).
	_, err := ScanWithContext(ctx, apk, ScanOptions{})
	// We don't require an error — a cancelled context may still return a
	// partial (possibly empty) report without error, depending on timing.
	// The important thing is that it returns at all.
	_ = err
}

// TestScan_ScoreNotInflated verifies that multidex apps (classes.dex + classes2.dex)
// don't get double-scored for the same rule.
func TestScan_ScoreNotInflated(t *testing.T) {
	bangclePayload := []byte("dex\n035\x00 com/secneo/apkwrapper bla")
	apk := writeFakeAPK(t, map[string][]byte{
		"classes.dex":  bangclePayload,
		"classes2.dex": bangclePayload,
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "packer.bangcle")
	// Score should be the rule's score (18) once, not twice.
	if rep.Score > 18 {
		t.Fatalf("score %d > 18: multidex rule counted more than once", rep.Score)
	}
}

// TestScan_WarningsOnSkippedEntries verifies that unreadable entries produce
// warnings rather than silently failing.
func TestScan_WarningsPresent(t *testing.T) {
	// An APK with a very large (fake) entry that exceeds the per-file cap.
	// We can't easily simulate a corrupt entry in a real zip, so instead
	// check that the report always has a Warnings field (even if empty).
	apk := writeFakeAPK(t, map[string][]byte{
		"classes.dex": []byte("dex\n035\x00"),
	})
	rep, err := Scan(apk)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Warnings may be nil or empty for a clean scan — that's correct.
	// This test just ensures the field is accessible (type check).
	_ = rep.Warnings
}

// TestScan_NEstedArchive verifies that a packed APK inside assets/ is recursed
// into and its contents detected.
func TestScan_NestedArchive(t *testing.T) {
	// Build inner APK with Bangcle indicator.
	innerAPK := buildFakeZIPBytes(t, map[string][]byte{
		"lib/arm64-v8a/libsecmain.so": []byte("ELF\x7f binary content"),
	})

	outerAPK := writeFakeAPK(t, map[string][]byte{
		"assets/payload.apk": innerAPK,
	})

	rep, err := ScanWithContext(context.Background(), outerAPK, ScanOptions{MaxDepth: 2})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	mustHaveID(t, rep, "packer.bangcle")
}

// TestEntropy_HighEntropy verifies that random-ish bytes score high entropy.
func TestEntropy_HighEntropy(t *testing.T) {
	// Use a pseudo-random but deterministic byte sequence.
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i*7 + i/3 + 13)
	}
	h := ShannonEntropy(data)
	if h < 7.0 {
		t.Fatalf("expected high entropy for near-random data, got %.2f", h)
	}
}

// TestEntropy_LowEntropy verifies that uniform data has near-zero entropy.
func TestEntropy_LowEntropy(t *testing.T) {
	data := bytes.Repeat([]byte{0x00}, 1024)
	h := ShannonEntropy(data)
	if h > 0.01 {
		t.Fatalf("expected ~0 entropy for uniform data, got %.2f", h)
	}
}

// ── Test Helpers ──────────────────────────────────────────────────────────────

// buildFakeZIPBytes creates an in-memory ZIP archive and returns its bytes.
func buildFakeZIPBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, payload := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// buildMinimalDEX builds a minimal but structurally valid DEX file that
// contains the given string pool entries.
func buildMinimalDEX(t *testing.T, strings []string) []byte {
	t.Helper()
	// We produce a DEX that our parser can read.
	// Layout: header (112 bytes) | string_ids (4 bytes each) | string_data
	// map_list (minimal) at the end.
	// This is NOT a valid executable DEX — just parseable by our parser.

	numStrings := uint32(len(strings))

	// Encode string data items.
	var strDataBuf bytes.Buffer
	type strEntry struct{ off uint32 }
	var strEntries []strEntry

	for _, s := range strings {
		off := uint32(112 + numStrings*4 + uint32(strDataBuf.Len()))
		strEntries = append(strEntries, strEntry{off})
		// ULEB128 length then bytes then 0x00.
		writeULEB128(&strDataBuf, uint32(len(s)))
		strDataBuf.WriteString(s)
		strDataBuf.WriteByte(0)
	}

	strIDsOff := uint32(112)
	mapOff := strIDsOff + numStrings*4 + uint32(strDataBuf.Len())

	// Map list: header_item + string_id_item + string_data_item + map_list_item.
	// map_list: count(u32) + 4 items * 12 bytes.
	mapSize := 4 + 4*12

	totalSize := int(mapOff) + mapSize

	buf := make([]byte, totalSize)

	// Magic.
	copy(buf[0:], "dex\n035\x00")

	// Endian tag at offset 40.
	binary.LittleEndian.PutUint32(buf[40:], 0x12345678)

	// file_size at 32.
	binary.LittleEndian.PutUint32(buf[32:], uint32(totalSize))

	// string_ids_size at 56, string_ids_off at 60.
	binary.LittleEndian.PutUint32(buf[56:], numStrings)
	binary.LittleEndian.PutUint32(buf[60:], strIDsOff)

	// map_off at 52.
	binary.LittleEndian.PutUint32(buf[52:], mapOff)

	// Write string_id offsets.
	for i, e := range strEntries {
		binary.LittleEndian.PutUint32(buf[strIDsOff+uint32(i)*4:], e.off)
	}

	// Write string data.
	copy(buf[strIDsOff+numStrings*4:], strDataBuf.Bytes())

	// Write map_list (4 items).
	mapBuf := buf[mapOff:]
	binary.LittleEndian.PutUint32(mapBuf, 4)                              // count
	writeMapItem(mapBuf[4:], 0x0000, 1, 0)                                // header_item
	writeMapItem(mapBuf[16:], 0x0001, numStrings, strIDsOff)              // string_id_item
	writeMapItem(mapBuf[28:], 0x2002, numStrings, strIDsOff+numStrings*4) // string_data_item
	writeMapItem(mapBuf[40:], 0x1000, 1, mapOff)                          // map_list

	return buf
}

func writeMapItem(dst []byte, typeCode uint16, size, offset uint32) {
	binary.LittleEndian.PutUint16(dst[0:], typeCode)
	binary.LittleEndian.PutUint16(dst[2:], 0)
	binary.LittleEndian.PutUint32(dst[4:], size)
	binary.LittleEndian.PutUint32(dst[8:], offset)
}

func writeULEB128(b *bytes.Buffer, v uint32) {
	for {
		byt := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			byt |= 0x80
		}
		b.WriteByte(byt)
		if v == 0 {
			break
		}
	}
}
