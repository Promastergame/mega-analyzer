package media3d

import (
	"encoding/binary"
	"strings"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────

type rawChunk struct {
	tag  string
	data []byte
}

func pad4(b []byte, fill byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, fill)
	}
	return b
}

func buildGLB(version uint32, chunks ...rawChunk) []byte {
	var body []byte
	for _, c := range chunks {
		var hdr [8]byte
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(c.data)))
		tag := []byte(c.tag)
		for len(tag) < 4 {
			tag = append(tag, 0)
		}
		copy(hdr[4:8], tag[:4])
		body = append(body, hdr[:]...)
		body = append(body, c.data...)
	}
	out := make([]byte, 12, 12+len(body))
	binary.LittleEndian.PutUint32(out[0:4], Magic)
	binary.LittleEndian.PutUint32(out[4:8], version)
	binary.LittleEndian.PutUint32(out[8:12], uint32(12+len(body)))
	return append(out, body...)
}

func buildLegacyGLB(jsonPart, body []byte) []byte {
	out := make([]byte, 20)
	binary.LittleEndian.PutUint32(out[0:4], Magic)
	binary.LittleEndian.PutUint32(out[4:8], 1)
	binary.LittleEndian.PutUint32(out[8:12], uint32(20+len(jsonPart)+len(body)))
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(jsonPart)))
	binary.LittleEndian.PutUint32(out[16:20], 0)
	out = append(out, jsonPart...)
	return append(out, body...)
}

func minimalDoc() []byte {
	return pad4([]byte(`{"asset":{"version":"2.0"}}`), ' ')
}

func hasSubstring(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ── container ───────────────────────────────────────────────────────────

func TestReadContainerRejectsNonGLB(t *testing.T) {
	if _, err := ReadContainer([]byte("short")); err != ErrShortHeader {
		t.Errorf("want ErrShortHeader, got %v", err)
	}
	if _, err := ReadContainer([]byte("NOPEnotaglbfile")); err != ErrNotGLB {
		t.Errorf("want ErrNotGLB, got %v", err)
	}
}

func TestReadContainerSplitsStandardChunks(t *testing.T) {
	data := buildGLB(2,
		rawChunk{"JSON", minimalDoc()},
		rawChunk{"BIN\x00", []byte("abcd")},
	)
	c, err := ReadContainer(data)
	if err != nil {
		t.Fatalf("ReadContainer: %v", err)
	}
	if c.Version != 2 {
		t.Errorf("version = %d, want 2", c.Version)
	}
	if len(c.Chunks) != 2 {
		t.Fatalf("chunks = %d, want 2", len(c.Chunks))
	}
	if c.Chunks[0].Kind != KindJSON || c.Chunks[1].Kind != KindBIN {
		t.Errorf("kinds = %v/%v, want json/bin", c.Chunks[0].Kind, c.Chunks[1].Kind)
	}
	if len(c.Anomalies) != 0 {
		t.Errorf("a clean container should have no anomalies, got %v", c.Anomalies)
	}
}

func TestFindNormalisesTagPadding(t *testing.T) {
	data := buildGLB(2,
		rawChunk{"JSON", minimalDoc()},
		rawChunk{"BIN\x00", []byte("abcd")},
	)
	c, err := ReadContainer(data)
	if err != nil {
		t.Fatalf("ReadContainer: %v", err)
	}
	// The tag on disk is "BIN\x00"; both spellings must resolve to it.
	for _, q := range []string{"BIN", "BIN\x00"} {
		got, ok := c.Find(q)
		if !ok {
			t.Fatalf("Find(%q) missed the BIN chunk", q)
		}
		if string(got) != "abcd" {
			t.Errorf("Find(%q) = %q, want \"abcd\"", q, got)
		}
	}
}

// The headline case. A container whose first chunk is a vendor FlatBuffers
// scene is a structurally valid GLB that no stock glTF loader will open,
// because the specification requires the JSON chunk to come first.
func TestVendorFirstChunkIsNotStockLoadable(t *testing.T) {
	data := buildGLB(2,
		rawChunk{"FLA2", []byte("meta")},
		rawChunk{"BIN\x00", []byte("xyz\x00")},
	)
	r := Probe(data)

	if r.Kind != "glb" {
		t.Fatalf("Kind = %q, want glb", r.Kind)
	}
	if r.HasJSON {
		t.Error("there is no JSON chunk in this container")
	}
	if r.StockLoadable {
		t.Error("a container with no JSON chunk must not be reported as stock-loadable")
	}
	if !contains(r.VendorChunks, "FLA2") {
		t.Errorf("VendorChunks = %v, want it to name FLA2", r.VendorChunks)
	}
	if !hasSubstring(r.Blockers, "first chunk") {
		t.Errorf("Blockers = %v, want the first-chunk rule to be cited", r.Blockers)
	}
	if !hasSubstring(r.Blockers, "no JSON chunk") {
		t.Errorf("Blockers = %v, want the missing JSON chunk to be cited", r.Blockers)
	}
}

func TestVendorChunkPayloadIsStillReachable(t *testing.T) {
	data := buildGLB(2, rawChunk{"FLA2", []byte("meta")})
	c, err := ReadContainer(data)
	if err != nil {
		t.Fatalf("ReadContainer: %v", err)
	}
	got, ok := c.Find("FLA2")
	if !ok || string(got) != "meta" {
		t.Errorf("Find(FLA2) = %q/%v, want \"meta\"/true", got, ok)
	}
	if c.Chunks[0].Kind != KindVendor {
		t.Errorf("FLA2 kind = %v, want vendor", c.Chunks[0].Kind)
	}
}

func TestLegacyVersionOneUsesADifferentHeader(t *testing.T) {
	data := buildLegacyGLB(minimalDoc(), []byte("binarybody!!"))
	r := Probe(data)

	if r.Kind != "glb1" {
		t.Fatalf("Kind = %q, want glb1", r.Kind)
	}
	if !r.HasJSON {
		t.Error("the version 1 layout still carries JSON, at offset 20")
	}
	if r.AssetVersion != "2.0" {
		t.Errorf("AssetVersion = %q; the JSON payload should still have been read", r.AssetVersion)
	}
	if r.StockLoadable {
		t.Error("a glTF 1.0 container must not be called stock-loadable by a 2.0 reader")
	}
	if !hasSubstring(r.Blockers, "glTF 1.0") {
		t.Errorf("Blockers = %v, want the 1.0 container to be cited", r.Blockers)
	}
}

func TestTruncatedChunkIsClampedNotFatal(t *testing.T) {
	full := buildGLB(2, rawChunk{"JSON", minimalDoc()}, rawChunk{"BIN\x00", []byte("abcdefgh")})
	cut := full[:len(full)-5]

	c, err := ReadContainer(cut)
	if err != nil {
		t.Fatalf("a truncated container should still parse: %v", err)
	}
	last := c.Chunks[len(c.Chunks)-1]
	if !last.Truncated {
		t.Error("the final chunk should be flagged truncated")
	}
	if len(last.Data) > last.Length {
		t.Errorf("Data (%d) must never exceed the declared Length (%d)", len(last.Data), last.Length)
	}
	if !hasSubstring(c.Anomalies, "truncated") && !hasSubstring(c.Anomalies, "only") {
		t.Errorf("Anomalies = %v, want the shortfall recorded", c.Anomalies)
	}
}

func TestTrailingBytesAfterContainerAreReported(t *testing.T) {
	data := buildGLB(2, rawChunk{"JSON", minimalDoc()})
	data = append(data, []byte("APPENDEDPAYLOAD")...)

	c, err := ReadContainer(data)
	if err != nil {
		t.Fatalf("ReadContainer: %v", err)
	}
	if !hasSubstring(c.Anomalies, "trailing") {
		t.Errorf("Anomalies = %v, want appended bytes reported", c.Anomalies)
	}
}

func TestChunkTableCannotSpinOnZeroLengthChunks(t *testing.T) {
	// Every iteration must advance by at least the 8-byte chunk header, or a
	// crafted file would hang the walker.
	data := buildGLB(2,
		rawChunk{"AAAA", nil},
		rawChunk{"BBBB", nil},
		rawChunk{"JSON", minimalDoc()},
	)
	c, err := ReadContainer(data)
	if err != nil {
		t.Fatalf("ReadContainer: %v", err)
	}
	if len(c.Chunks) != 3 {
		t.Errorf("chunks = %d, want 3", len(c.Chunks))
	}
}

// ── document ────────────────────────────────────────────────────────────

// The spec says pad the JSON chunk with spaces. Producers pad with NUL, and
// encoding/json rejects that, so a readable asset would fail to parse.
func TestParseDocumentToleratesNulPadding(t *testing.T) {
	payload := pad4([]byte(`{"asset":{"version":"2.0"}}`), 0x00)
	doc, err := ParseDocument(payload)
	if err != nil {
		t.Fatalf("NUL-padded JSON should still parse: %v", err)
	}
	if doc.Asset.Version != "2.0" {
		t.Errorf("version = %q, want 2.0", doc.Asset.Version)
	}
}

func TestGeometryRespectsPrimitiveMode(t *testing.T) {
	// mode 4 (triangles) is the default: 9 indices are 3 faces.
	tri := `{"asset":{"version":"2.0"},
		"accessors":[{"count":9},{"count":6}],
		"meshes":[{"primitives":[{"indices":0,"attributes":{"POSITION":1}}]}]}`
	// mode 5 (triangle strip): 10 indices are 8 faces, not 3.
	strip := `{"asset":{"version":"2.0"},
		"accessors":[{"count":10},{"count":8}],
		"meshes":[{"primitives":[{"mode":5,"indices":0,"attributes":{"POSITION":1}}]}]}`
	// mode 1 (lines) has no faces at all.
	lines := `{"asset":{"version":"2.0"},
		"accessors":[{"count":12},{"count":12}],
		"meshes":[{"primitives":[{"mode":1,"indices":0,"attributes":{"POSITION":1}}]}]}`

	cases := []struct {
		name           string
		src            string
		verts, faces   int
	}{
		{"triangles", tri, 6, 3},
		{"strip", strip, 8, 8},
		{"lines", lines, 12, 0},
	}
	for _, tc := range cases {
		doc, err := ParseDocument([]byte(tc.src))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		v, f, _ := doc.Geometry()
		if v != tc.verts || f != tc.faces {
			t.Errorf("%s: got %d verts / %d faces, want %d / %d", tc.name, v, f, tc.verts, tc.faces)
		}
	}
}

func TestNonIndexedPrimitiveStillCounts(t *testing.T) {
	src := `{"asset":{"version":"2.0"},
		"accessors":[{"count":9}],
		"meshes":[{"primitives":[{"attributes":{"POSITION":0}}]}]}`
	doc, err := ParseDocument([]byte(src))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	v, f, _ := doc.Geometry()
	if v != 9 || f != 3 {
		t.Errorf("got %d verts / %d faces, want 9 / 3", v, f)
	}
}

func TestExternalResourcesIgnoreDataURIs(t *testing.T) {
	src := `{"asset":{"version":"2.0"},
		"buffers":[{"byteLength":4,"uri":"scene.bin"},{"byteLength":4,"uri":"data:application/octet-stream;base64,AAAA"},{"byteLength":4}],
		"images":[{"uri":"albedo.png"}]}`
	doc, err := ParseDocument([]byte(src))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	got := doc.ExternalResources()
	if len(got) != 2 || got[0] != "scene.bin" || got[1] != "albedo.png" {
		t.Errorf("ExternalResources = %v, want [scene.bin albedo.png]", got)
	}
}

func TestParseVersionShapes(t *testing.T) {
	cases := []struct {
		in           string
		maj, mn      int
		ok           bool
	}{
		{"2.0", 2, 0, true},
		{"2.1", 2, 1, true},
		{"2.0.1", 2, 0, true},
		{"1.0", 1, 0, true},
		{"2", 2, 0, true},
		{"", 0, 0, false},
		{"two point oh", 0, 0, false},
	}
	for _, tc := range cases {
		maj, mn, ok := parseVersion(tc.in)
		if maj != tc.maj || mn != tc.mn || ok != tc.ok {
			t.Errorf("parseVersion(%q) = %d,%d,%v; want %d,%d,%v",
				tc.in, maj, mn, ok, tc.maj, tc.mn, tc.ok)
		}
	}
}

// ── extensions ─────────────────────────────────────────────────────────

func TestExtensionRegistryIsPopulated(t *testing.T) {
	if n := KnownExtensionCount(); n < 30 {
		t.Fatalf("registry holds %d entries; an emptied table would silently mark every extension unknown", n)
	}
	for _, name := range []string{
		"KHR_draco_mesh_compression",
		"EXT_meshopt_compression",
		"KHR_texture_basisu",
		"EXT_texture_webp",
		"KHR_mesh_quantization",
	} {
		info, ok := LookupExtension(name)
		if !ok {
			t.Errorf("%s missing from the registry", name)
			continue
		}
		if !info.Ratified {
			t.Errorf("%s is a ratified Khronos extension but is not marked so", name)
		}
	}
}

func TestRegistryNamesMatchTheirKeys(t *testing.T) {
	for key, info := range extensionRegistry {
		if key != info.Name {
			t.Errorf("registry key %q holds Name %q", key, info.Name)
		}
	}
}

func probeJSONOnly(t *testing.T, src string) Report {
	t.Helper()
	return Probe(buildGLB(2, rawChunk{"JSON", pad4([]byte(src), ' ')}))
}

func TestRequiredUnknownExtensionBlocksLoading(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.0"},
		"extensionsUsed":["SUPERCELL_wizardry"],
		"extensionsRequired":["SUPERCELL_wizardry"]}`)

	if !contains(r.Unrecognized, "SUPERCELL_wizardry") {
		t.Errorf("Unrecognized = %v, want the unknown extension named", r.Unrecognized)
	}
	if r.StockLoadable {
		t.Error("a REQUIRED unknown extension must block loading")
	}
	if !hasSubstring(r.Blockers, "SUPERCELL_wizardry") {
		t.Errorf("Blockers = %v, want the extension named", r.Blockers)
	}
}

func TestOptionalUnknownExtensionDoesNotBlock(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.0"},
		"extensionsUsed":["SUPERCELL_wizardry"]}`)

	if !contains(r.Unrecognized, "SUPERCELL_wizardry") {
		t.Errorf("Unrecognized = %v, want the unknown extension named", r.Unrecognized)
	}
	if !r.StockLoadable {
		t.Errorf("an OPTIONAL unknown extension is the graceful-degradation path; blockers were %v", r.Blockers)
	}
	if !hasSubstring(r.Anomalies, "optional") {
		t.Errorf("Anomalies = %v, want the optional extension noted", r.Anomalies)
	}
}

func TestCompressionAndCodecExtensionsAreClassified(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.0"},
		"extensionsUsed":["KHR_draco_mesh_compression","KHR_texture_basisu","EXT_meshopt_compression"]}`)

	if !contains(r.GeometryCompression, "KHR_draco_mesh_compression") ||
		!contains(r.GeometryCompression, "EXT_meshopt_compression") {
		t.Errorf("GeometryCompression = %v", r.GeometryCompression)
	}
	if !contains(r.TextureCodecs, "KHR_texture_basisu") {
		t.Errorf("TextureCodecs = %v", r.TextureCodecs)
	}
	if !r.StockLoadable {
		t.Errorf("known optional extensions must not block; blockers were %v", r.Blockers)
	}
}

func TestRequiredExtensionMissingFromUsedIsAnAnomaly(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.0"},
		"extensionsRequired":["KHR_texture_basisu"]}`)
	if !hasSubstring(r.Anomalies, "missing from extensionsUsed") {
		t.Errorf("Anomalies = %v, want the used/required mismatch reported", r.Anomalies)
	}
}

// ── version gates ──────────────────────────────────────────────────────

func TestMissingAssetVersionBlocks(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"generator":"nothing"}}`)
	if r.StockLoadable {
		t.Error("asset.version is the one mandatory member; its absence must block")
	}
	if !hasSubstring(r.Blockers, "asset.version") {
		t.Errorf("Blockers = %v", r.Blockers)
	}
}

func TestMinVersionAboveBaselineBlocks(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.1","minVersion":"2.1"}}`)
	if r.StockLoadable {
		t.Error("minVersion 2.1 must be refused by a baseline 2.0 loader")
	}
	if !hasSubstring(r.Blockers, "minVersion") {
		t.Errorf("Blockers = %v", r.Blockers)
	}
}

// A 2.x document with no minVersion floor is forward compatible by design and
// must NOT be blocked, or every future minor release reads as broken.
func TestForwardCompatibleMinorVersionLoads(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.1"}}`)
	if !r.StockLoadable {
		t.Errorf("2.1 without a minVersion floor is forward compatible; blockers were %v", r.Blockers)
	}
}

func TestGltfOneDocumentIsRejected(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"1.0"}}`)
	if r.StockLoadable {
		t.Error("a 1.0 document is not loadable by a 2.0 reader")
	}
}

// ── top level ─────────────────────────────────────────────────────────

func TestProbeAcceptsBareGltfJSON(t *testing.T) {
	r := Probe([]byte(`{"asset":{"version":"2.0"},"buffers":[{"byteLength":4,"uri":"a.bin"}]}`))
	if r.Kind != "gltf" {
		t.Fatalf("Kind = %q, want gltf", r.Kind)
	}
	if !r.StockLoadable {
		t.Errorf("blockers = %v", r.Blockers)
	}
	if !hasSubstring(r.Anomalies, "external resource") {
		t.Errorf("Anomalies = %v, want the external .bin noted", r.Anomalies)
	}
}

func TestProbeOnRubbishIsEmptyNotPanicking(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		{},
		[]byte("x"),
		[]byte("not a model at all"),
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
	} {
		r := Probe(in)
		if r.Kind != "" {
			t.Errorf("Probe(%q) claimed kind %q", in, r.Kind)
		}
		if r.Summary() != "not a glTF asset" {
			t.Errorf("Summary = %q", r.Summary())
		}
	}
}

func TestSummaryNamesVendorChunksAndVerdict(t *testing.T) {
	r := Probe(buildGLB(2, rawChunk{"FLA2", []byte("meta")}))
	s := r.Summary()
	if !strings.Contains(s, "FLA2") {
		t.Errorf("Summary = %q, want the vendor chunk named", s)
	}
	if !strings.Contains(s, "NOT stock-loadable") {
		t.Errorf("Summary = %q, want the verdict stated", s)
	}
}

func TestCountsCoverEveryCoreArray(t *testing.T) {
	r := probeJSONOnly(t, `{"asset":{"version":"2.0"},
		"scenes":[{}],"nodes":[{},{}],"materials":[{}],"textures":[{}],
		"images":[{"mimeType":"image/png"}],"samplers":[{}],"bufferViews":[{},{}],
		"buffers":[{"byteLength":8}],"animations":[{}],"skins":[{}],"cameras":[{}],
		"accessors":[{"count":3}],
		"meshes":[{"primitives":[{"attributes":{"POSITION":0}},{"attributes":{"POSITION":0}}]}]}`)

	c := r.Counts
	if c.Scenes != 1 || c.Nodes != 2 || c.Meshes != 1 || c.Primitives != 2 ||
		c.Materials != 1 || c.Textures != 1 || c.Images != 1 || c.Samplers != 1 ||
		c.Accessors != 1 || c.BufferViews != 2 || c.Buffers != 1 ||
		c.Animations != 1 || c.Skins != 1 || c.Cameras != 1 {
		t.Errorf("Counts = %+v", c)
	}
	if !contains(r.ImageMimeTypes, "image/png") {
		t.Errorf("ImageMimeTypes = %v", r.ImageMimeTypes)
	}
}
