package apkloader

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestImportSetHashStable(t *testing.T) {
	a := []string{"CreateFileA:kernel32.dll", "FindResourceA:kernel32.dll"}
	b := []string{"FindResourceA:kernel32.dll", "CreateFileA:kernel32.dll"}
	if importSetHash(a) != importSetHash(b) {
		t.Error("same import set in different order must hash equal (builder clustering)")
	}
	if importSetHash(a) == "" {
		t.Error("non-empty import set must hash non-empty")
	}
	if importSetHash(nil) != "" || importSetHash([]string{"", "  "}) != "" {
		t.Error("empty import set must hash empty")
	}
	if importSetHash([]string{"KERNEL32.DLL.CreateFileA"}) != importSetHash([]string{"kernel32.dll.createfilea"}) {
		t.Error("hash must be case-insensitive")
	}
}

func TestPayloadSectionAnomaly(t *testing.T) {
	if ok, _ := payloadSectionAnomaly(".rsrc", 34<<20, 8.0); !ok {
		t.Error("34 MB entropy-8.0 .rsrc must flag")
	}
	for _, tc := range []struct {
		name string
		size uint64
		ent  float64
	}{
		{".text", 1 << 20, 6.0},
		{".rsrc", 100 << 10, 8.0},
		{".rsrc", 34 << 20, 4.0},
	} {
		if ok, _ := payloadSectionAnomaly(tc.name, tc.size, tc.ent); ok {
			t.Errorf("payloadSectionAnomaly(%s, %d, %.1f) = true, want false", tc.name, tc.size, tc.ent)
		}
	}
}

func TestOverlaySize(t *testing.T) {
	if got := overlaySize(100, [][2]uint64{{0, 60}, {60, 30}}); got != 10 {
		t.Errorf("overlay = %d, want 10", got)
	}
	if got := overlaySize(90, [][2]uint64{{0, 60}, {60, 30}}); got != 0 {
		t.Errorf("no overlay must be 0, got %d", got)
	}
}

func TestDropperComboSeverity(t *testing.T) {
	full := map[string]bool{
		"findresourcea": true, "loadresource": true, "lockresource": true,
		"sizeofresource": true, "createfilea": true, "writefile": true,
		"gettemppatha": true,
	}
	fired, sev, detail := dropperComboSeverity(full, true)
	if !fired || sev != "high" {
		t.Errorf("full combo + anomaly = (%v,%q), want (true,high)", fired, sev)
	}
	if !strings.Contains(detail, "temp") {
		t.Errorf("staging note missing: %q", detail)
	}
	if fired, sev, _ := dropperComboSeverity(full, false); !fired || sev != "medium" {
		t.Errorf("full combo alone = (%v,%q), want (true,medium)", fired, sev)
	}
	// Missing the file-write half: no combo.
	partial := map[string]bool{"findresourcea": true, "lockresource": true}
	if fired, _, _ := dropperComboSeverity(partial, true); fired {
		t.Error("resource-only imports must not fire the combo")
	}
}

func vbinderBlob(markers ...string) []byte {
	return []byte("MZ\x90\x00" + strings.Join(markers, "\x00") + "\x00")
}

func TestVBinderSignalsHigh(t *testing.T) {
	data := vbinderBlob(append(vbinderDynAPIs,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		"ping -n 3 127.0.0.1")...)
	got := vbinderSignals(data, 4<<10, 34<<20, true)
	if len(got) != 1 {
		t.Fatalf("full residue + stub = %d findings, want 1", len(got))
	}
	if got[0].ID != "vbinder-residue" || got[0].Severity != "high" {
		t.Errorf("got (%q,%q), want (vbinder-residue,high)", got[0].ID, got[0].Severity)
	}
}

func TestVBinderSignalsMedium(t *testing.T) {
	// Cluster without the stub silhouette still fires medium.
	data := vbinderBlob("RtlDecompressBuffer", "SHGetSpecialFolderPathA",
		"PathAddBackslashA", "RegCreateKeyExA",
		`Software\Microsoft\Windows\CurrentVersion\Run`)
	got := vbinderSignals(data, 0, 0, false)
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Errorf("cluster without stub = %+v, want one medium", got)
	}
}

func TestVBinderSignalsQuiet(t *testing.T) {
	// A lone Run-key path (legit installers carry one) must stay silent.
	if got := vbinderSignals(vbinderBlob(`Software\Microsoft\Windows\CurrentVersion\Run`), 0, 0, false); len(got) != 0 {
		t.Errorf("lone Run key fired: %+v", got)
	}
	// One stray API name is noise.
	if got := vbinderSignals(vbinderBlob("ShellExecuteA"), 0, 0, false); len(got) != 0 {
		t.Errorf("single marker fired: %+v", got)
	}
	// Stub silhouette alone (NSIS-style installers) must stay silent.
	if got := vbinderSignals([]byte("MZ\x90\x00"), 4<<10, 34<<20, true); len(got) != 0 {
		t.Errorf("stub shape alone fired: %+v", got)
	}
	// Two markers = low cluster note, nothing louder.
	got := vbinderSignals(vbinderBlob("ShellExecuteA", "PathFindFileNameA"), 0, 0, false)
	if len(got) != 1 || got[0].Severity != "low" {
		t.Errorf("two markers = %+v, want one low", got)
	}
}

// --- RCDATA vault machinery ---

func putDir(buf []byte, at int, ids []uint32, subOffs []uint32) {
	putDirSub(buf, at, ids, subOffs, true)
}

// putDirSub writes a resource directory; lang-level entries point at data
// entries (no subdirectory bit), all other levels at subdirectories.
func putDirSub(buf []byte, at int, ids []uint32, offs []uint32, sub bool) {
	binary.LittleEndian.PutUint16(buf[at+12:], 0)
	binary.LittleEndian.PutUint16(buf[at+14:], uint16(len(ids)))
	for i, id := range ids {
		o := at + 16 + 8*i
		binary.LittleEndian.PutUint32(buf[o:], id)
		if sub {
			offs[i] |= 0x80000000
		}
		binary.LittleEndian.PutUint32(buf[o+4:], offs[i])
	}
}

func putDataEnt(buf []byte, at int, dataRVA, size uint32) {
	binary.LittleEndian.PutUint32(buf[at:], dataRVA)
	binary.LittleEndian.PutUint32(buf[at+4:], size)
}

// synthRsrc builds a minimal .rsrc image: RCDATA names 1,2 hold big blobs,
// RCDATA/4097 holds cfg, type 3 holds a decoy icon. rva is the section RVA.
func synthRsrc(rva uint32, big1, big2, cfg, icon []byte) []byte {
	raw := make([]byte, 0x300+len(big1)+len(big2)+len(cfg)+len(icon))
	putDir(raw, 0x00, []uint32{10, 3}, []uint32{0x20, 0x100})
	putDir(raw, 0x20, []uint32{1, 2, 4097}, []uint32{0x50, 0x70, 0x90})
	putDirSub(raw, 0x50, []uint32{0}, []uint32{0xB0}, false)
	putDirSub(raw, 0x70, []uint32{0}, []uint32{0xC0}, false)
	putDirSub(raw, 0x90, []uint32{0}, []uint32{0xD0}, false)
	putDir(raw, 0x100, []uint32{1}, []uint32{0x120})
	off := 0x200
	put := func(b []byte) uint32 {
		start := off
		copy(raw[start:], b)
		off += len(b)
		return rva + uint32(start)
	}
	putDataEnt(raw, 0xB0, put(big1), uint32(len(big1)))
	putDataEnt(raw, 0xC0, put(big2), uint32(len(big2)))
	putDataEnt(raw, 0xD0, put(cfg), uint32(len(cfg)))
	putDirSub(raw, 0x120, []uint32{0}, []uint32{0x140}, false)
	putDataEnt(raw, 0x140, put(icon), uint32(len(icon)))
	return raw
}

func xor16ENC(key, plain []byte) []byte {
	out := make([]byte, len(plain))
	for i, c := range plain {
		out[i] = c ^ key[i%len(key)]
	}
	return out
}

func TestParseRsrcBlobs(t *testing.T) {
	big := bytes.Repeat([]byte{0xCC}, 2<<20)
	cfg := bytes.Repeat([]byte{0xAB}, 169)
	raw := synthRsrc(0x5000, big, big, cfg, []byte("BMicon"))
	got := parseRsrcBlobs(raw, 0x5000)
	if len(got) != 4 {
		t.Fatalf("parsed %d blobs, want 4 (3 RCDATA + icon)", len(got))
	}
	byName := map[uint32]rsrcBlob{}
	for _, b := range got {
		if b.rtype == 10 {
			byName[b.name] = b
		}
	}
	if len(byName) != 3 || len(byName[1].data) != 2<<20 || len(byName[4097].data) != 169 {
		t.Errorf("RCDATA set wrong: %+v", byName)
	}
	if out := parseRsrcBlobs([]byte("garbage!!"), 0x5000); len(out) != 0 {
		t.Errorf("garbage must parse to nil, got %d", len(out))
	}
	if out := parseRsrcBlobs(nil, 0x5000); len(out) != 0 {
		t.Errorf("nil must parse to nil, got %d", len(out))
	}
}

func TestTryVBinderConfig(t *testing.T) {
	key := []byte("0123456789abcdef")
	plain := append([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x02\x00\x00\x00\x22\x00\x00\x00evil-payload.exe\x00C:\\Dir1\\SubDir\x00xeno.exe\x00")...)
	cfg := append(append([]byte{}, key...), xor16ENC(key, plain)...)
	names, back, ok := tryVBinderConfig(cfg)
	if !ok || !bytes.Equal(back, key) {
		t.Fatalf("valid config rejected (ok=%v)", ok)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "evil-payload.exe") || !strings.Contains(joined, "xeno.exe") {
		t.Errorf("drop names lost: %q", joined)
	}
	if _, _, ok := tryVBinderConfig(bytes.Repeat([]byte{0x77}, 169)); ok {
		t.Error("flat bytes must not decrypt")
	}
	if _, _, ok := tryVBinderConfig(append([]byte("MZ"), bytes.Repeat([]byte{1}, 100)...)); ok {
		t.Error("MZ-leading blob must be refused")
	}
	if _, _, ok := tryVBinderConfig([]byte("tiny")); ok {
		t.Error("short blob must be refused")
	}
}

func TestProbeVBinderStage(t *testing.T) {
	key := []byte("0123456789abcdef")
	blob := append(xor16ENC(key, []byte{0x02, 0, 0, 0, 0xF8, 0xFF, 0, 0}),
		bytes.Repeat([]byte{0x51}, 0xFFF8)...)
	fm, sz, ok := probeVBinderStage(blob, key)
	if !ok || fm != "XPRESS" || sz != 0xFFF8 {
		t.Errorf("probe = (%q,%d,%v), want (XPRESS,65528,true)", fm, sz, ok)
	}
	if _, _, ok := probeVBinderStage(bytes.Repeat([]byte{0x99}, 64), key); ok {
		t.Error("random header must not probe plausibly")
	}
}

func TestRsrcVaultHigh(t *testing.T) {
	// High-entropy fixed key: like the builder's random per-build key, it
	// keeps the ciphertext snarled (measured real-config entropy is 5.8).
	key := []byte{0x9b, 0x3f, 0xc7, 0x11, 0x8e, 0x02, 0xdd, 0x44, 0x7a, 0x50, 0xb6, 0xe9, 0x23, 0x6c, 0xa1, 0x5f}
	plain := append([]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x02\x00\x00\x00\x22\x00\x00\x00evil-payload.exe\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x00\x00C:\\Dir1\\SubDir\x00\x00\x00\x00\x00\x09\x00\x00\x00xeno.exe\x00")...)
	cfg := append(append([]byte{}, key...), xor16ENC(key, plain)...)
	mkStage := func(fm uint32, size int) []byte {
		hdr := make([]byte, 8)
		binary.LittleEndian.PutUint32(hdr[0:], fm)
		binary.LittleEndian.PutUint32(hdr[4:], uint32(size))
		return append(xor16ENC(key, hdr), bytes.Repeat([]byte{0x51}, size)...)
	}
	big1 := mkStage(0, 1<<20)
	big2 := mkStage(2, 1<<20)
	raw := synthRsrc(0x5000, big1, big2, cfg, []byte("BMicon"))
	got := rsrcVaultSignals(raw, 0x5000)
	if len(got) != 1 {
		t.Fatalf("vault+config = %d findings, want 1", len(got))
	}
	if got[0].ID != "rcdata-vault" || got[0].Severity != "high" {
		t.Errorf("got (%q,%q), want (rcdata-vault,high)", got[0].ID, got[0].Severity)
	}
	for _, want := range []string{"evil-payload.exe", "XPRESS", "raw"} {
		if !strings.Contains(got[0].Description, want) {
			t.Errorf("description missing %q: %s", want, got[0].Description)
		}
	}
}

func TestRsrcVaultMediumAndQuiet(t *testing.T) {
	big := bytes.Repeat([]byte{0xCC}, 2<<20)
	rnd := bytes.Repeat([]byte{0x3D}, 169) // small but undecryptable
	raw := synthRsrc(0x5000, big, big, rnd, []byte("BMicon"))
	got := rsrcVaultSignals(raw, 0x5000)
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Errorf("unconfirmed vault = %+v, want one medium", got)
	}
	// Single big blob: no vault.
	raw2 := synthRsrc(0x5000, big, bytes.Repeat([]byte{1}, 100), rnd, []byte("BMicon"))
	if got := rsrcVaultSignals(raw2, 0x5000); len(got) != 0 {
		t.Errorf("single stage fired: %+v", got)
	}
}

func TestBadBuilderHash(t *testing.T) {
	if _, ok := badBuilderHash["35b35c971266b8c601286be105c03606"]; !ok {
		t.Error("confirmed VBinder builder hash missing from denylist")
	}
	if _, ok := badBuilderHash["00000000000000000000000000000000"]; ok {
		t.Error("zero hash must not match")
	}
}
