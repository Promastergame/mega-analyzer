package pipeline

import (
	"bytes"
	"compress/zlib"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/types"
)

// buildEncryptedContainer builds the observed second-stage scheme:
// magic(4) + key(4) + zlib(payload) XOR key32[i%32] XOR key4[i%4].
func buildEncryptedContainer(t *testing.T, key32, key4, payload []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	body := z.Bytes()
	blob := make([]byte, 8+len(body))
	copy(blob[0:4], []byte{0xc9, 0x3b, 0x7a, 0x4f})
	copy(blob[4:8], key4)
	for i := range body {
		blob[8+i] = body[i] ^ key32[i%len(key32)] ^ key4[i%4]
	}
	return blob
}

// dexImage returns an incompressible pseudo-random body with a DEX magic so
// the container exceeds the 64 KiB size gate after compression. Deterministic
// (xorshift64) to keep tests reproducible. The DEX magic "dex" 0x0a "035" NUL
// is spelled as raw bytes to keep this file ASCII-only.
func dexImage() []byte {
	data := make([]byte, 256*1024)
	copy(data, []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00})
	seed := uint64(0x9e3779b97f4a7c15)
	for i := 8; i < len(data); i++ {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		data[i] = byte(seed >> 24)
	}
	return data
}

func TestRecoverEncryptedPayloadsFindsContainer(t *testing.T) {
	key32 := []byte{0x0b, 0x71, 0x90, 0xbd, 0xeb, 0x79, 0x32, 0xdb, 0x1e, 0x99, 0xb1, 0x70,
		0xfd, 0xc5, 0x15, 0xcb, 0x6b, 0xd4, 0x0e, 0x02, 0x96, 0x47, 0xba, 0x05,
		0xdf, 0x3c, 0x84, 0xbc, 0x44, 0x75, 0x6d, 0xf1}
	key4 := []byte{0xae, 0xe6, 0x65, 0x8c}
	payload := dexImage()

	dir := testutil.TempDir(t)
	assets := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "yxuuraugae.bin"),
		buildEncryptedContainer(t, key32, key4, payload), 0o644); err != nil {
		t.Fatal(err)
	}
	// A plain ZIP file must not be flagged.
	zipPayload := append([]byte{'P', 'K', 3, 4}, make([]byte, 1<<16)...)
	if err := os.WriteFile(filepath.Join(assets, "plain.zip"), zipPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{result: types.NewAnalysisResult(dir), fogKeys: newFogKeyRegistry()}
	p.registerFogKeyCandidate(key32)
	p.recoverEncryptedPayloads()

	if len(p.result.ArtifactFindings) != 1 {
		t.Fatalf("expected 1 recovered container, got %d: %+v",
			len(p.result.ArtifactFindings), p.result.ArtifactFindings)
	}
	f := p.result.ArtifactFindings[0]
	if f.Path != "assets/yxuuraugae.bin" {
		t.Fatalf("recovered wrong file: %s", f.Path)
	}
	if !bytes.Contains([]byte(f.Reason), []byte("DEX image")) {
		t.Fatalf("finding does not describe DEX payload: %s", f.Reason)
	}
}

func TestRecoverEncryptedPayloadsSkipsBenign(t *testing.T) {
	dir := testutil.TempDir(t)
	assets := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	// Compressed-but-benign text asset and a small file.
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte("just some long text config, no executable container here... "))
	zw.Write(bytes.Repeat([]byte("x"), 1<<16))
	zw.Close()
	if err := os.WriteFile(filepath.Join(assets, "text.cfg"), z.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "small.bin"), []byte{0xc9, 0x3b}, 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Pipeline{result: types.NewAnalysisResult(dir), fogKeys: newFogKeyRegistry()}
	p.registerFogKeyCandidate([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	p.recoverEncryptedPayloads()
	if len(p.result.ArtifactFindings) != 0 {
		t.Fatalf("benign assets flagged: %+v", p.result.ArtifactFindings)
	}
}

// The fog registry deduplicates and caps candidates.
func TestFogKeyRegistryDedup(t *testing.T) {
	r := newFogKeyRegistry()
	k := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if !r.register(k) {
		t.Fatal("first registration rejected")
	}
	if r.register(k) {
		t.Fatal("duplicate accepted")
	}
	if len(r.snapshot()) != 1 {
		t.Fatalf("registry size %d", len(r.snapshot()))
	}
}
