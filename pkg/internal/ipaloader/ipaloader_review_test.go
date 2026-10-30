package ipaloader

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Review round: plist routing, XML depth cap, modern privacy keys, fat64,
// .class exclusion, __entitlements scoping, triage sort order.

// ─── minimal bplist00 builder ────────────────────────────────────────────────

func buildTestBPlist(t *testing.T, kv map[string]string) []byte {
	t.Helper()
	type obj struct{ raw []byte }
	var objs []obj
	// obj0 placeholder for the top dict; real dict bytes appended last so we
	// know key/value object indices up front.
	keyIdx := map[string]int{}
	valIdx := map[string]int{}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	for _, k := range keys {
		keyIdx[k] = len(objs) + 1
		objs = append(objs, obj{raw: encodeTestASCIIString(k)})
		valIdx[k] = len(objs) + 1
		objs = append(objs, obj{raw: encodeTestASCIIString(kv[k])})
	}
	dict := []byte{0xD0 | byte(len(keys))}
	for _, k := range keys {
		dict = append(dict, byte(keyIdx[k]))
	}
	for _, k := range keys {
		dict = append(dict, byte(valIdx[k]))
	}
	all := append([]obj{{raw: dict}}, objs...)

	buf := []byte("bplist00")
	offsets := make([]uint64, len(all))
	for i, o := range all {
		offsets[i] = uint64(len(buf))
		buf = append(buf, o.raw...)
	}
	tableOff := uint64(len(buf))
	for _, off := range offsets {
		buf = append(buf, byte(off)) // all < 256: offsetSize 1
	}
	trailer := make([]byte, 32)
	trailer[6] = 1 // offsetSize
	trailer[7] = 1 // objRefSize
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(all)))
	binary.BigEndian.PutUint64(trailer[16:24], 0) // topObject
	binary.BigEndian.PutUint64(trailer[24:32], tableOff)
	return append(buf, trailer...)
}

func encodeTestASCIIString(s string) []byte {
	if len(s) < 15 {
		return append([]byte{0x50 | byte(len(s))}, s...)
	}
	return append([]byte{0x5F, 0x10, byte(len(s))}, s...)
}

func writeTempPlist(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Info.plist")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReviewBinaryPlistContainingXMLMarker(t *testing.T) {
	// The stored string itself contains "<?xml": routing must stay binary.
	data := buildTestBPlist(t, map[string]string{"CFBundleIdentifier": "A<?xmlB"})
	meta, err := ParseInfoPlist(writeTempPlist(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if meta.BundleID != "A<?xmlB" {
		t.Errorf("binary plist misrouted to XML parser: BundleID = %q", meta.BundleID)
	}
}

// ─── XML depth cap ───────────────────────────────────────────────────────────

func nestTestPlist(t *testing.T, depth int) []byte {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><plist><dict>`)
	sb.WriteString(`<key>CFBundleIdentifier</key><string>com.x</string><key>sub</key>`)
	for i := 0; i < depth; i++ {
		sb.WriteString(`<dict><key>k</key>`)
	}
	sb.WriteString(`<string>v</string>`)
	for i := 0; i < depth; i++ {
		sb.WriteString(`</dict>`)
	}
	sb.WriteString(`</dict></plist>`)
	return []byte(sb.String())
}

func TestReviewXMLPlistDepthCap(t *testing.T) {
	// Shallow nesting: top-level keys resolve, subtree decodes to a map.
	meta, err := ParseInfoPlist(writeTempPlist(t, nestTestPlist(t, 10)))
	if err != nil {
		t.Fatal(err)
	}
	if meta.BundleID != "com.x" {
		t.Errorf("shallow plist broke: BundleID = %q", meta.BundleID)
	}
	if m := decodeXMLPlistRoot(nestTestPlist(t, 10)); m == nil {
		t.Fatal("shallow root is nil")
	} else if _, ok := m["sub"].(map[string]interface{}); !ok {
		t.Errorf("shallow subtree should decode to a map, got %T", m["sub"])
	}
	// Hostile nesting: top-level keys still resolve, and the subtree walk
	// terminates at the cap (nil) instead of recursing 500 frames deep to
	// the "v" leaf an uncapped parser would return.
	meta, err = ParseInfoPlist(writeTempPlist(t, nestTestPlist(t, 500)))
	if err != nil {
		t.Fatal(err)
	}
	if meta.BundleID != "com.x" {
		t.Errorf("deep nesting broke top-level keys: BundleID = %q", meta.BundleID)
	}
	m := decodeXMLPlistRoot(nestTestPlist(t, 500))
	if m == nil {
		t.Fatal("deep root is nil")
	}
	depth := 0
	cur := m["sub"]
	for {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			break
		}
		cur = mm["k"]
		depth++
		if depth > 1000 {
			t.Fatal("subtree walk did not terminate")
		}
	}
	if cur != nil {
		t.Errorf("capped walk should end in nil, got %v", cur)
	}
	if depth > maxXMLPlistDepth+2 {
		t.Errorf("subtree decoded %d levels deep, cap is %d", depth, maxXMLPlistDepth)
	}
}

// ─── modern privacy keys ─────────────────────────────────────────────────────

func TestReviewModernPrivacyKeys(t *testing.T) {
	plist := `<?xml version="1.0"?><plist><dict>` +
		`<key>CFBundleIdentifier</key><string>com.x</string>` +
		`<key>NSUserTrackingUsageDescription</key><string>ads</string>` +
		`<key>NSLocalNetworkUsageDescription</key><string>lan</string>` +
		`<key>NSCalendarsUsageDescription</key><string>cal</string>` +
		`</dict></plist>`
	meta, err := ParseInfoPlist(writeTempPlist(t, []byte(plist)))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"NSUserTrackingUsageDescription", "NSLocalNetworkUsageDescription", "NSCalendarsUsageDescription"} {
		if meta.Permissions[k] == "" {
			t.Errorf("modern privacy key %q not surfaced", k)
		}
	}
}

// ─── Mach-O magics ───────────────────────────────────────────────────────────

func TestReviewFat64Magic(t *testing.T) {
	for _, m := range [][]byte{
		{0xCA, 0xFE, 0xBA, 0xBF}, // FAT_MAGIC_64
		{0xBF, 0xBA, 0xFE, 0xCA}, // FAT_CIGAM_64
	} {
		if !isMachOMagicBytes(m) {
			t.Errorf("fat64 magic %X not recognized", m)
		}
	}
}

func TestReviewClassFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	// Java class magic collides with Mach-O fat magic.
	if err := os.WriteFile(filepath.Join(dir, "A.class"),
		[]byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "App"),
		[]byte{0xCF, 0xFA, 0xED, 0xFE, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	bins, _ := findMachOBinaries(context.Background(), dir)
	if len(bins) != 1 || !strings.HasSuffix(bins[0], "App") {
		t.Errorf("expected only the Mach-O binary, got %v", bins)
	}
}

// ─── __entitlements scoping ──────────────────────────────────────────────────

func buildTestMachOWithEntitlements(t *testing.T, blob, decoy []byte) []byte {
	t.Helper()
	const (
		headerSize  = 32
		segSize     = 72
		sectSize    = 80
		blobOff     = headerSize + segSize + sectSize
		lcSegment64 = 0x19
	)
	total := blobOff + len(blob) + len(decoy)
	buf := new(bytes.Buffer)
	// 0xFEEDFACF stored LE == on-disk bytes CF FA ED FE (MH_MAGIC_64).
	hdr := []uint32{0xFEEDFACF, 0x0100000C, 0, 2, 1, segSize + sectSize, 0, 0}
	for _, v := range hdr {
		binary.Write(buf, binary.LittleEndian, v)
	}
	binary.Write(buf, binary.LittleEndian, uint32(lcSegment64))
	binary.Write(buf, binary.LittleEndian, uint32(segSize+sectSize))
	segname := make([]byte, 16)
	copy(segname, "__TEXT")
	buf.Write(segname)
	binary.Write(buf, binary.LittleEndian, uint64(0))      // vmaddr
	binary.Write(buf, binary.LittleEndian, uint64(0x1000)) // vmsize
	binary.Write(buf, binary.LittleEndian, uint64(0))      // fileoff
	binary.Write(buf, binary.LittleEndian, uint64(total))  // filesize
	binary.Write(buf, binary.LittleEndian, int32(7))       // maxprot
	binary.Write(buf, binary.LittleEndian, int32(5))       // initprot
	binary.Write(buf, binary.LittleEndian, uint32(1))      // nsects
	binary.Write(buf, binary.LittleEndian, uint32(0))      // flags
	sectname := make([]byte, 16)
	copy(sectname, "__entitlements")
	buf.Write(sectname)
	buf.Write(segname)
	binary.Write(buf, binary.LittleEndian, uint64(0))         // addr
	binary.Write(buf, binary.LittleEndian, uint64(len(blob))) // size
	binary.Write(buf, binary.LittleEndian, uint32(blobOff))   // offset
	binary.Write(buf, binary.LittleEndian, uint32(0))         // align
	binary.Write(buf, binary.LittleEndian, uint32(0))         // reloff
	binary.Write(buf, binary.LittleEndian, uint32(0))         // nreloc
	binary.Write(buf, binary.LittleEndian, uint32(0))         // flags
	binary.Write(buf, binary.LittleEndian, uint32(0))         // res1
	binary.Write(buf, binary.LittleEndian, uint32(0))         // res2
	binary.Write(buf, binary.LittleEndian, uint32(0))         // res3
	buf.Write(blob)
	buf.Write(decoy)
	if buf.Len() != total {
		t.Fatalf("fixture size %d != %d", buf.Len(), total)
	}
	return buf.Bytes()
}

func TestReviewEntitlementsPreferSection(t *testing.T) {
	blob := []byte(`<dict><key>com.apple.test.ent</key><true/></dict>`)
	decoy := []byte("\x00<key>com.decoy.notent</key>\x00")
	data := buildTestMachOWithEntitlements(t, blob, decoy)
	if entitlementsSection(data) == nil {
		t.Fatal("section lookup failed on the fixture itself")
	}
	keys := entitlementKeys(data)
	if len(keys) != 1 || keys[0] != "com.apple.test.ent" {
		t.Errorf("section scoping failed, got %v", keys)
	}
}

// ─── triage sort order ───────────────────────────────────────────────────────

func TestReviewSortFindingsTriageOrder(t *testing.T) {
	f := []types.ArtifactFinding{
		{Path: "b", Severity: types.SeverityInfo, Reason: "r"},
		{Path: "a", Severity: types.SeverityHigh, Reason: "r"},
		{Path: "c", Severity: types.SeverityCritical, Reason: "r"},
	}
	sortFindings(f)
	want := []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityInfo}
	for i, s := range want {
		if f[i].Severity != s {
			t.Errorf("position %d: severity = %v, want %v", i, f[i].Severity, s)
		}
	}
}
