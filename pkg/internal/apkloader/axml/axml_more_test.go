package axml

import (
	archivezip "archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// api.go
// ---------------------------------------------------------------------------

func TestIsBinaryXML_ShortBuffer(t *testing.T) {
	if IsBinaryXML([]byte{0x03}) {
		t.Error("too-short buffer should return false")
	}
	if IsBinaryXML(nil) {
		t.Error("nil should return false")
	}
}

func TestIsBinaryXML_PlainText(t *testing.T) {
	if IsBinaryXML([]byte(`<?xml version="1.0"?>`)) {
		t.Error("plain text XML should return false")
	}
}

func TestRender_MinimalAXML(t *testing.T) {
	data := buildMinimalAXML(t)
	xml, err := Render(data)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(xml, "<manifest") {
		t.Errorf("rendered XML missing <manifest: %s", xml)
	}
}

func TestRender_Error(t *testing.T) {
	_, err := Render([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Error("expected error on bad magic")
	}
}

func TestSummary_Nil(t *testing.T) {
	var m *Manifest
	s := m.Summary()
	if s != "<nil manifest>" {
		t.Errorf("got %q", s)
	}
}

func TestSummary_Populated(t *testing.T) {
	m := &Manifest{
		Package:     "com.foo",
		VersionCode: 7,
		VersionName: "1.0",
		MinSDK:      21,
		TargetSDK:   33,
		Permissions: []string{"perm.A"},
		Activities:  []Component{{Name: "Main"}},
	}
	s := m.Summary()
	if !strings.Contains(s, "com.foo") {
		t.Errorf("summary missing package: %s", s)
	}
	if !strings.Contains(s, "versionCode=7") {
		t.Errorf("summary missing versionCode: %s", s)
	}
}

func TestExportedComponents(t *testing.T) {
	yes := true
	no := false
	m := &Manifest{
		Activities: []Component{
			{Name: "Explicit", Exported: &yes},
			{Name: "Implicit", IntentFilts: []IntentFilter{{Actions: []string{"act"}}}},
			{Name: "Hidden", Exported: &no},
			{Name: "Private"},
		},
		Services: []Component{
			{Name: "Svc", Exported: &yes},
		},
	}
	got := m.ExportedComponents()
	if len(got) != 3 {
		t.Errorf("expected 3 exported, got %d: %v", len(got), got)
	}
}

func TestDecodeFile_Missing(t *testing.T) {
	_, err := DecodeFile("no_such_file_xyz.xml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDecodeFile_ValidFixture(t *testing.T) {
	data := buildMinimalAXML(t)
	tmp := filepath.Join(t.TempDir(), "manifest.xml")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatal(err)
	}
	m, err := DecodeFile(tmp)
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if m.Package != "com.example" {
		t.Errorf("package=%q", m.Package)
	}
}

// ---------------------------------------------------------------------------
// strings.go — stringPool methods
// ---------------------------------------------------------------------------

func TestStringPool_LenAndHas(t *testing.T) {
	p := &stringPool{entries: []string{"a", "b", "c"}}
	if p.Len() != 3 {
		t.Errorf("Len()=%d", p.Len())
	}
	if !p.Has(0) || !p.Has(2) {
		t.Error("Has should return true for valid indices")
	}
	if p.Has(3) {
		t.Error("Has(3) should be false")
	}
	if p.Has(0xFFFFFFFF) {
		t.Error("Has(0xFFFFFFFF) should be false")
	}

	// nil pool
	var np *stringPool
	if np.Len() != 0 {
		t.Error("nil Len should be 0")
	}
	if np.Has(0) {
		t.Error("nil Has should be false")
	}
	if np.String(0) != SentinelNoString {
		t.Errorf("nil String should be sentinel, got %q", np.String(0))
	}
}

func TestDecodePoolEntry_UTF8ShortCharCount(t *testing.T) {
	// UTF-8 with multi-byte char count (high bit set)
	// char count = 1 (encoded as 0x81, 0x01 → 0x0101 but just use single overlong form)
	// byte len = 5 bytes
	// payload = "hello"
	buf := []byte{
		0x81, 0x00, // char count (high bit set, 2-byte form): 0x81 & 0x7F = 1, total = (1 << 8) | 0 = 256 — wait need simpler
	}
	// Let's build a valid simple short UTF-8 pool entry
	// char count = 5 (< 0x80, single byte), byte count = 5, payload = "world"
	buf2 := []byte{5, 5, 'w', 'o', 'r', 'l', 'd', 0}
	got, err := decodePoolEntry(buf2, true)
	if err != nil {
		t.Fatalf("decodePoolEntry: %v", err)
	}
	if got != "world" {
		t.Errorf("got %q", got)
	}
	_ = buf
}

func TestDecodePoolEntry_UTF8LongByteCount(t *testing.T) {
	// char count single byte = 5
	// byte count with high bit: 0x80|0 = 0x80, then 5 → byteLen = (0 << 8) | 5 = 5
	buf := []byte{5, 0x80, 5, 'h', 'e', 'l', 'l', 'o', 0}
	got, err := decodePoolEntry(buf, true)
	if err != nil {
		t.Fatalf("decodePoolEntry: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestDecodePoolEntry_UTF8LongCharCount(t *testing.T) {
	// char count with high bit set (2-byte form)
	// 0x80 | hi-byte, lo-byte: total = (hi << 8) | lo
	// char count = (0 << 8) | 3 = 3  → in[0]=0x80, in[1]=3
	// byte count = 3 (single byte)
	// payload = "abc"
	buf := []byte{0x80, 3, 3, 'a', 'b', 'c', 0}
	got, err := decodePoolEntry(buf, true)
	if err != nil {
		t.Fatalf("decodePoolEntry long char count: %v", err)
	}
	if got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestDecodePoolEntry_UTF16LongCharCount(t *testing.T) {
	// UTF-16 with long char count (high bit set in first u16)
	// first u16 = 0x8000 (hi=0, lo=0 → charCount = (0 << 16) | 0 = 0)
	// Actually let's encode "Hi": charCount=2, payload=H\0i\0 + \0\0
	var buf [12]byte
	binary.LittleEndian.PutUint16(buf[0:2], 2) // charCount=2, high bit clear (normal)
	buf[2] = 'H'
	buf[3] = 0
	buf[4] = 'i'
	buf[5] = 0
	got, err := decodePoolEntry(buf[:], false)
	if err != nil {
		t.Fatalf("decodePoolEntry UTF16: %v", err)
	}
	if got != "Hi" {
		t.Errorf("got %q", got)
	}
}

func TestDecodePoolEntry_UTF16_LongForm(t *testing.T) {
	// Long form UTF-16: first u16 has high bit set (0x8000 | hi), second u16 = lo
	// charCount = (hi << 16) | lo. Let's use charCount = 2, so hi=0,lo=2
	// first u16 = 0x8000 | 0 = 0x8000
	var buf [12]byte
	binary.LittleEndian.PutUint16(buf[0:2], 0x8000) // high bit set, hi=0
	binary.LittleEndian.PutUint16(buf[2:4], 2)      // lo=2 → charCount=2
	buf[4] = 'A'
	buf[5] = 0
	buf[6] = 'B'
	buf[7] = 0
	got, err := decodePoolEntry(buf[:], false)
	if err != nil {
		t.Fatalf("decodePoolEntry UTF16 long form: %v", err)
	}
	if got != "AB" {
		t.Errorf("got %q", got)
	}
}

func TestDecodePoolEntry_TooShort(t *testing.T) {
	_, err := decodePoolEntry([]byte{0x01}, false)
	if err == nil {
		t.Error("expected error for 1-byte buf")
	}
}

func TestDecodePoolEntry_UTF8TruncatedCharCount(t *testing.T) {
	// High bit set on first byte but only 1 byte total → truncated
	_, err := decodePoolEntry([]byte{0x80}, true)
	if err == nil {
		t.Error("expected truncated error")
	}
}

func TestDecodePoolEntry_UTF8TruncatedByteCount(t *testing.T) {
	// Valid char count (single byte = 5), then buf ends before byte count
	_, err := decodePoolEntry([]byte{5}, true)
	if err == nil {
		t.Error("expected truncated error for missing byte count")
	}
}

func TestDecodePoolEntry_UTF8PayloadOverruns(t *testing.T) {
	// byte count claims 100 bytes but buf is short
	_, err := decodePoolEntry([]byte{1, 100, 'x'}, true)
	if err == nil {
		t.Error("expected overrun error")
	}
}

func TestContainsSurrogateTriplet_False(t *testing.T) {
	if containsSurrogateTriplet([]byte("hello world")) {
		t.Error("plain ASCII has no surrogate triplets")
	}
}

func TestDecodeCESU8_AllBranches(t *testing.T) {
	// Continuation byte without lead byte (c < 0xC0)
	got := decodeCESU8([]byte{0x80})
	if got != string([]rune{'�'}) {
		t.Errorf("unexpected: %q", got)
	}

	// 2-byte sequence but truncated (only 1 byte)
	got2 := decodeCESU8([]byte{0xC2})
	if got2 != string([]rune{'�'}) {
		t.Errorf("2-byte truncated: %q", got2)
	}

	// 3-byte sequence but truncated (only 2 bytes; i+2 = 2 >= len 2)
	got3 := decodeCESU8([]byte{0xE2, 0x80})
	// decodeCESU8 emits replacement for each leading byte without enough continuation
	if !strings.ContainsRune(got3, '�') {
		t.Errorf("3-byte truncated should contain replacement char: %q", got3)
	}

	// 4-byte sequence — valid canonical UTF-8 (U+1F600 = F0 9F 98 80)
	got4 := decodeCESU8([]byte{0xF0, 0x9F, 0x98, 0x80})
	if got4 != "\U0001F600" {
		t.Errorf("4-byte: got %q", got4)
	}

	// 4-byte truncated (only 3 bytes; i+3 = 3 >= len 3)
	got5 := decodeCESU8([]byte{0xF0, 0x9F, 0x98})
	if !strings.ContainsRune(got5, '�') {
		t.Errorf("4-byte truncated should contain replacement: %q", got5)
	}

	// High surrogate without matching low (3-byte)
	// U+D83D = ED A0 BD, followed by a non-surrogate 3-byte sequence (3-byte but not 0xE0-0xEF)
	hiSurrogate := []byte{0xED, 0xA0, 0xBD, 0x41} // high surrogate then 'A'
	got6 := decodeCESU8(hiSurrogate)
	if !strings.ContainsRune(got6, 'A') {
		t.Errorf("unexpected result: %q", got6)
	}

	// Regular 2-byte sequence (U+00E9 = é, encoded as C3 A9)
	got7 := decodeCESU8([]byte{0xC3, 0xA9})
	if got7 != "é" {
		t.Errorf("2-byte é: got %q", got7)
	}

	// CESU-8 surrogate pair (U+1F600)
	cesu := []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}
	got8 := decodeCESU8(cesu)
	if got8 != "\U0001F600" {
		t.Errorf("CESU-8: got %q", got8)
	}
}

// ---------------------------------------------------------------------------
// arsc_types.go — ResourceTable methods
// ---------------------------------------------------------------------------

func buildSimpleResourceTable() *ResourceTable {
	return &ResourceTable{
		GlobalStrings: []string{"hello", "world"},
		Packages: []ResourcePackage{
			{
				ID:   0x7f,
				Name: "com.example",
				TypeIDs: map[string]uint32{
					"string": 1,
				},
				Types: []ResourceType{
					{
						ID:   1,
						Name: "string",
						Entries: []ResourceEntry{
							{
								ID:   0,
								Name: "app_name",
								Values: []ConfigValue{
									{Config: "default", Value: "MyApp", RawType: typeString},
								},
							},
							{
								ID:   1,
								Name: "greeting",
								Values: []ConfigValue{
									{Config: "ru", Value: "Привет"},
									{Config: "default", Value: "Hello"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestResolveID_Found(t *testing.T) {
	table := buildSimpleResourceTable()
	// ID: pkg=0x7f, type=0x01, entry=0x0000 → 0x7f010000
	entry := table.ResolveID(0x7f010000)
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.Name != "app_name" {
		t.Errorf("got %q", entry.Name)
	}
}

func TestResolveID_NotFound(t *testing.T) {
	table := buildSimpleResourceTable()
	if entry := table.ResolveID(0x7f020000); entry != nil {
		t.Error("expected nil for unknown type")
	}
	if entry := table.ResolveID(0x7e010000); entry != nil {
		t.Error("expected nil for unknown package")
	}
}

func TestResolveDefault_DefaultConfig(t *testing.T) {
	table := buildSimpleResourceTable()
	val := table.ResolveDefault(0x7f010000)
	if val != "MyApp" {
		t.Errorf("got %q", val)
	}
}

func TestResolveDefault_FallbackFirstValue(t *testing.T) {
	// Entry with no "default" config, should return first value
	table := &ResourceTable{
		Packages: []ResourcePackage{
			{
				ID:      0x7f,
				Name:    "test",
				TypeIDs: map[string]uint32{"drawable": 2},
				Types: []ResourceType{
					{
						ID:   2,
						Name: "drawable",
						Entries: []ResourceEntry{
							{
								ID:   0,
								Name: "icon",
								Values: []ConfigValue{
									{Config: "xxhdpi", Value: "icon_xxhdpi.png"},
								},
							},
						},
					},
				},
			},
		},
	}
	val := table.ResolveDefault(0x7f020000)
	if val != "icon_xxhdpi.png" {
		t.Errorf("got %q", val)
	}
}

func TestResolveDefault_Unknown(t *testing.T) {
	table := buildSimpleResourceTable()
	if val := table.ResolveDefault(0x00000000); val != "" {
		t.Errorf("expected empty, got %q", val)
	}
}

func TestResolveName(t *testing.T) {
	table := buildSimpleResourceTable()
	name := table.ResolveName(0x7f010001)
	if name != "@string/greeting" {
		t.Errorf("got %q", name)
	}

	// Unknown
	if name := table.ResolveName(0x7f030000); name != "" {
		t.Errorf("expected empty for unknown, got %q", name)
	}
}

// ---------------------------------------------------------------------------
// resolve.go
// ---------------------------------------------------------------------------

func TestResolveManifest_NilSafety(t *testing.T) {
	// neither should panic
	ResolveManifest(nil, nil)
	ResolveManifest(&Manifest{MetaData: map[string]string{}}, nil)
	ResolveManifest(nil, &ResourceTable{})
}

func TestResolveManifest_ResolvesRefs(t *testing.T) {
	table := &ResourceTable{
		Packages: []ResourcePackage{
			{
				ID:      0x7f,
				Name:    "com.test",
				TypeIDs: map[string]uint32{"string": 1},
				Types: []ResourceType{
					{
						ID:   1,
						Name: "string",
						Entries: []ResourceEntry{
							{
								ID:   0,
								Name: "app_name",
								Values: []ConfigValue{
									{Config: "default", Value: "TestApp"},
								},
							},
						},
					},
				},
			},
		},
	}

	m := &Manifest{
		MetaData: map[string]string{},
		Application: ApplicationInfo{
			Label: "@0x7f010000",
			Icon:  "@0x7f020000", // won't resolve
		},
		Activities: []Component{
			{Name: "Main", Permission: "@0x7f010000"},
		},
	}
	m.XMLBytes = []byte(`<manifest android:label="@0x7f010000"></manifest>`)
	ResolveManifest(m, table)

	if m.Application.Label != "TestApp" {
		t.Errorf("label=%q", m.Application.Label)
	}
	if m.Activities[0].Permission != "TestApp" {
		t.Errorf("permission=%q", m.Activities[0].Permission)
	}
	// Editable XML keeps the resource reference; analysis fields resolve it.
	if !strings.Contains(string(m.XMLBytes), "@string/app_name") {
		t.Errorf("XML not rewritten: %s", m.XMLBytes)
	}
}

func TestResolveManifest_ResolvesName(t *testing.T) {
	table := buildSimpleResourceTable()
	m := &Manifest{
		MetaData: map[string]string{},
		Application: ApplicationInfo{
			Theme:         "@0x7f010000",
			NetworkSecCfg: "@0x7f020000", // unknown → resolved by name
		},
	}
	m.XMLBytes = []byte("")
	ResolveManifest(m, table)
	// Theme has a default value "MyApp"
	if m.Application.Theme != "MyApp" {
		t.Errorf("theme=%q", m.Application.Theme)
	}
}

func TestRewriteXMLReferences_NoMarker(t *testing.T) {
	input := `<manifest package="com.example"></manifest>`
	got := rewriteXMLReferences(input, &ResourceTable{})
	if got != input {
		t.Errorf("should be unchanged, got: %s", got)
	}
}

func TestRewriteXMLReferences_UnclosedQuote(t *testing.T) {
	input := `="@0x7f010000`
	got := rewriteXMLReferences(input, &ResourceTable{})
	// Should handle gracefully (no panic)
	_ = got
}

func TestResolveRefString_NotRef(t *testing.T) {
	got := resolveRefString("plain-string", &ResourceTable{})
	if got != "plain-string" {
		t.Errorf("got %q", got)
	}
}

func TestResolveRefString_BadHex(t *testing.T) {
	got := resolveRefString("@ZZZZZZZZ", &ResourceTable{})
	if got != "@ZZZZZZZZ" {
		t.Errorf("got %q", got)
	}
}

func TestResolveRefString_KnownRef(t *testing.T) {
	table := buildSimpleResourceTable()
	got := resolveRefString("@0x7f010000", table)
	if got != "@string/app_name" {
		t.Errorf("got %q", got)
	}
}

func TestResolveRefString_NameFallback(t *testing.T) {
	table := buildSimpleResourceTable()
	// A default string value must not replace the resource reference.
	got := resolveRefString("@0x7f010001", table)
	if got != "@string/greeting" {
		t.Errorf("got %q", got)
	}
}

func TestResolveString_NonRef(t *testing.T) {
	s := "not-a-ref"
	resolveString(&s, &ResourceTable{})
	if s != "not-a-ref" {
		t.Errorf("got %q", s)
	}
}

// ---------------------------------------------------------------------------
// public_xml.go
// ---------------------------------------------------------------------------

func TestEscXML_Escaping(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"a<b", "a&lt;b"},
		{"a>b", "a&gt;b"},
		{`a"b`, "a&quot;b"},
		{"a&b", "a&amp;b"},
		{"a'b", "a&apos;b"},
	}
	for _, tc := range cases {
		got := escXML(tc.in)
		if got != tc.want {
			t.Errorf("escXML(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGeneratePublicXML_Empty(t *testing.T) {
	table := &ResourceTable{}
	xml := table.GeneratePublicXML()
	if !strings.Contains(xml, "<resources>") {
		t.Errorf("missing root element: %s", xml)
	}
}

func TestGeneratePublicXML_WithEntries(t *testing.T) {
	table := buildSimpleResourceTable()
	xml := table.GeneratePublicXML()
	if !strings.Contains(xml, "app_name") {
		t.Errorf("missing app_name: %s", xml)
	}
	if !strings.Contains(xml, `type="string"`) {
		t.Errorf("missing type: %s", xml)
	}
}

// ---------------------------------------------------------------------------
// arsc.go — ParseARSC errors
// ---------------------------------------------------------------------------

func TestParseARSC_TooSmall(t *testing.T) {
	_, err := ParseARSC([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error")
	}
}

func TestParseARSC_WrongMagic(t *testing.T) {
	buf := make([]byte, 20)
	binary.LittleEndian.PutUint16(buf[0:2], 0x1234)
	binary.LittleEndian.PutUint16(buf[2:4], 12)
	binary.LittleEndian.PutUint32(buf[4:8], 20)
	_, err := ParseARSC(buf)
	if err == nil {
		t.Error("expected error on wrong magic")
	}
}

func TestParseARSC_MinimalValid(t *testing.T) {
	// Build a minimal valid ARSC: RES_TABLE chunk header + one string pool chunk
	buf := buildMinimalARSC()
	table, err := ParseARSC(buf)
	if err != nil {
		t.Fatalf("ParseARSC: %v", err)
	}
	if table == nil {
		t.Fatal("got nil table")
	}
}

func TestReadChunkHeader_Truncated(t *testing.T) {
	_, _, _, err := readChunkHeader([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for truncated chunk header")
	}
}

func TestReadChunkHeader_TinyHeader(t *testing.T) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint16(buf[0:2], 0x0001)
	binary.LittleEndian.PutUint16(buf[2:4], 4) // hdr < 8
	binary.LittleEndian.PutUint32(buf[4:8], 8)
	_, _, _, err := readChunkHeader(buf)
	if err == nil {
		t.Error("expected error for hdr < 8")
	}
}

func TestReadChunkHeader_SizeLTHeader(t *testing.T) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint16(buf[0:2], 0x0001)
	binary.LittleEndian.PutUint16(buf[2:4], 8)
	binary.LittleEndian.PutUint32(buf[4:8], 4) // size < hdr
	_, _, _, err := readChunkHeader(buf)
	if err == nil {
		t.Error("expected error for size < hdr")
	}
}

func TestMergeTypeEntries(t *testing.T) {
	into := &ResourceType{
		ID:   1,
		Name: "string",
		Entries: []ResourceEntry{
			{ID: 0, Name: "a", Values: []ConfigValue{{Config: "default", Value: "A"}}},
		},
	}
	add := ResourceType{
		ID:   1,
		Name: "string",
		Entries: []ResourceEntry{
			// Same ID: should merge values
			{ID: 0, Name: "a", Values: []ConfigValue{{Config: "ru", Value: "А"}}},
			// New ID: should be appended
			{ID: 1, Name: "b", Values: []ConfigValue{{Config: "default", Value: "B"}}},
		},
	}
	mergeTypeEntries(into, add)
	if len(into.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(into.Entries))
	}
	if len(into.Entries[0].Values) != 2 {
		t.Errorf("expected 2 values on entry 0, got %d", len(into.Entries[0].Values))
	}
}

func TestDecodeFixedUTF16_ASCII(t *testing.T) {
	// "Test" in UTF-16LE
	buf := []byte{'T', 0, 'e', 0, 's', 0, 't', 0, 0, 0, 0, 0}
	got := decodeFixedUTF16(buf)
	if got != "Test" {
		t.Errorf("got %q", got)
	}
}

func TestResolveStringRefs_Basic(t *testing.T) {
	table := &ResourceTable{
		GlobalStrings: []string{"zero", "one", "two"},
		Packages: []ResourcePackage{
			{
				ID:   0x7f,
				Name: "test",
				Types: []ResourceType{
					{
						ID:   1,
						Name: "string",
						Entries: []ResourceEntry{
							{
								ID:   0,
								Name: "s0",
								Values: []ConfigValue{
									{Config: "default", Value: "strpool:1"},
								},
							},
						},
					},
				},
			},
		},
	}
	table.resolveStringRefs()
	val := table.Packages[0].Types[0].Entries[0].Values[0].Value
	if val != "one" {
		t.Errorf("expected 'one', got %q", val)
	}
}

func TestParseStrpoolIdx_EdgeCases(t *testing.T) {
	// Empty number after prefix
	idx, ok := parseStrpoolIdx("strpool:")
	if !ok || idx != 0 {
		t.Errorf("empty suffix: got %d, %v", idx, ok)
	}
}

// ---------------------------------------------------------------------------
// exporter.go
// ---------------------------------------------------------------------------

func TestResolveAttrName_Known(t *testing.T) {
	got := resolveAttrName(0x0101000f) // "debuggable"
	if got != "android:debuggable" {
		t.Errorf("got %q", got)
	}
}

func TestResolveAttrName_Unknown(t *testing.T) {
	got := resolveAttrName(0xdeadbeef)
	if !strings.HasPrefix(got, "?") {
		t.Errorf("expected ?hex form, got %q", got)
	}
}

func TestResolvePluralQuantity(t *testing.T) {
	cases := map[uint32]string{
		0x01000004: "other",
		0x01000005: "zero",
		0x01000006: "one",
		0x01000007: "two",
		0x01000008: "few",
		0x01000009: "many",
		0xdeadbeef: "0xdeadbeef",
	}
	for id, want := range cases {
		got := resolvePluralQuantity(id)
		if got != want {
			t.Errorf("resolvePluralQuantity(0x%x)=%q, want %q", id, got, want)
		}
	}
}

func TestExportTable_Empty(t *testing.T) {
	table := &ResourceTable{}
	outDir := t.TempDir()
	if err := ExportTable(table, outDir); err != nil {
		t.Fatalf("ExportTable: %v", err)
	}
}

func TestExportTable_WithEntries(t *testing.T) {
	table := &ResourceTable{
		Packages: []ResourcePackage{
			{
				ID:      0x7f,
				Name:    "com.example",
				TypeIDs: map[string]uint32{"string": 1, "color": 2, "style": 3, "array": 4, "plurals": 5},
				Types: []ResourceType{
					{
						ID:   1,
						Name: "string",
						Entries: []ResourceEntry{
							{
								ID:     0,
								Name:   "app_name",
								Values: []ConfigValue{{Config: "default", Value: "TestApp"}},
							},
							{
								ID:     1,
								Name:   "greeting",
								Values: []ConfigValue{{Config: "ru", Value: "Привет"}},
							},
						},
					},
					{
						ID:   2,
						Name: "color",
						Entries: []ResourceEntry{
							{
								ID:     0,
								Name:   "accent",
								Values: []ConfigValue{{Config: "default", Value: "#ff0000"}},
							},
						},
					},
					{
						ID:   3,
						Name: "style",
						Entries: []ResourceEntry{
							{
								ID:    0,
								Name:  "AppTheme",
								IsBag: true,
								Values: []ConfigValue{
									{
										Config: "default",
										Value:  "@android:style/Theme",
										Parent: "@android:style/Theme",
										ComplexValues: []ComplexValue{
											{NameID: 0x0101000f, Value: "false", RawType: typeIntBoolean},
										},
									},
								},
							},
						},
					},
					{
						ID:   4,
						Name: "array",
						Entries: []ResourceEntry{
							{
								ID:    0,
								Name:  "days",
								IsBag: true,
								Values: []ConfigValue{
									{
										Config: "default",
										ComplexValues: []ComplexValue{
											{NameID: 0, Value: "Mon"},
											{NameID: 1, Value: "Tue"},
										},
									},
								},
							},
						},
					},
					{
						ID:   5,
						Name: "plurals",
						Entries: []ResourceEntry{
							{
								ID:    0,
								Name:  "items_count",
								IsBag: true,
								Values: []ConfigValue{
									{
										Config: "default",
										ComplexValues: []ComplexValue{
											{NameID: 0x01000006, Value: "1 item"},
											{NameID: 0x01000004, Value: "%d items"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	outDir := t.TempDir()
	if err := ExportTable(table, outDir); err != nil {
		t.Fatalf("ExportTable: %v", err)
	}
	// Check strings.xml was created
	stringsFile := filepath.Join(outDir, "values", "strings.xml")
	if _, err := os.Stat(stringsFile); err != nil {
		t.Errorf("strings.xml not created: %v", err)
	}
	data, _ := os.ReadFile(stringsFile)
	if !strings.Contains(string(data), "TestApp") {
		t.Errorf("strings.xml missing TestApp: %s", data)
	}
}

// ---------------------------------------------------------------------------
// framework.go — nil safety
// ---------------------------------------------------------------------------

func TestFrameworkResolver_NilSafety(t *testing.T) {
	var fr *FrameworkResolver
	if got := fr.ResolveName(0x01010003); got != "" {
		t.Errorf("nil ResolveName should be empty, got %q", got)
	}
	if got := fr.ResolveAttributeName(0x01010003); got != "" {
		t.Errorf("nil ResolveAttributeName should be empty, got %q", got)
	}

	fr2 := &FrameworkResolver{table: nil}
	if got := fr2.ResolveName(0x01010003); got != "" {
		t.Errorf("nil table ResolveName should be empty, got %q", got)
	}
}

func TestFrameworkResolver_ResolveAttributeName_WrongPkg(t *testing.T) {
	fr := &FrameworkResolver{table: buildSimpleResourceTable()}
	// Package 0x7f is not framework (0x01), so should return ""
	if got := fr.ResolveAttributeName(0x7f010000); got != "" {
		t.Errorf("expected empty for non-framework ID, got %q", got)
	}
}

func TestLoadFrameworkAPK_Missing(t *testing.T) {
	_, err := LoadFrameworkAPK("no_such_file.apk")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildMinimalARSC constructs the smallest valid resources.arsc buffer:
// RES_TABLE header + one global string pool (empty).
func buildMinimalARSC() []byte {
	// Build an empty string pool chunk.
	poolChunk := buildEmptyStringPoolChunk()

	// Build the RES_TABLE header.
	totalSize := uint32(12 + len(poolChunk))
	buf := make([]byte, totalSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkTable)
	binary.LittleEndian.PutUint16(buf[2:4], 12)
	binary.LittleEndian.PutUint32(buf[4:8], totalSize)
	binary.LittleEndian.PutUint32(buf[8:12], 0) // packageCount
	copy(buf[12:], poolChunk)
	return buf
}

// buildEmptyStringPoolChunk builds a minimal RES_STRING_POOL_TYPE chunk with 0 entries.
func buildEmptyStringPoolChunk() []byte {
	// generic chunk header (8) + pool-specific header (20) = 28 bytes total
	const size = 28
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:2], chunkStringPool)
	binary.LittleEndian.PutUint16(buf[2:4], size) // headerSize
	binary.LittleEndian.PutUint32(buf[4:8], size) // chunkSize
	// stringCount=0, styleCount=0, flags=UTF8, stringsStart=28, stylesStart=0
	binary.LittleEndian.PutUint32(buf[8:12], 0)         // stringCount
	binary.LittleEndian.PutUint32(buf[12:16], 0)        // styleCount
	binary.LittleEndian.PutUint32(buf[16:20], flagUTF8) // flags
	binary.LittleEndian.PutUint32(buf[20:24], size)     // stringsStart
	binary.LittleEndian.PutUint32(buf[24:28], 0)        // stylesStart
	return buf
}

// ---------------------------------------------------------------------------
// arsc.go — parseTablePackage, parseTableType, parseTableEntry, parseTableLibrary
// ---------------------------------------------------------------------------

// buildStringPoolChunkWithEntries builds a minimal UTF-8 string pool chunk
// containing the given strings. The returned []byte is a valid pool chunk.
func buildStringPoolChunkWithEntries(strs []string) []byte {
	// Build raw string data
	var sbuf []byte
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(len(sbuf))
		sbuf = append(sbuf, byte(len(s)), byte(len(s)))
		sbuf = append(sbuf, []byte(s)...)
		sbuf = append(sbuf, 0) // NUL terminator
	}
	// 4-byte align
	for len(sbuf)%4 != 0 {
		sbuf = append(sbuf, 0)
	}

	// pool-specific header: 20 bytes + offset table + data
	const poolSpecificHdrSize = 20
	headerSize := 8 + poolSpecificHdrSize
	stringsStart := uint32(headerSize + len(offsets)*4)
	totalSize := int(stringsStart) + len(sbuf)

	buf := make([]byte, totalSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkStringPool)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(totalSize))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(strs))) // stringCount
	binary.LittleEndian.PutUint32(buf[12:16], 0)                // styleCount
	binary.LittleEndian.PutUint32(buf[16:20], flagUTF8)         // flags
	binary.LittleEndian.PutUint32(buf[20:24], stringsStart)     // stringsStart
	binary.LittleEndian.PutUint32(buf[24:28], 0)                // stylesStart

	for i, off := range offsets {
		binary.LittleEndian.PutUint32(buf[headerSize+i*4:], off)
	}
	copy(buf[stringsStart:], sbuf)
	return buf
}

// buildTablePackageChunk builds a minimal RES_TABLE_PACKAGE_TYPE chunk with
// type/key string pools and one typeSpec + one type chunk.
// This exercises parseTablePackage, parseTableType and parseTableEntry.
func buildTablePackageChunk(t *testing.T) []byte {
	t.Helper()

	typeStrs := []string{"string"} // 1 type
	keyStrs := []string{"app_name"}

	typePool := buildStringPoolChunkWithEntries(typeStrs)
	keyPool := buildStringPoolChunkWithEntries(keyStrs)

	// typeSpec chunk: 1 entry, ID=1
	const typeSpecHdrSize = 16
	typeSpec := make([]byte, typeSpecHdrSize+4) // 4 bytes for 1 entry flag
	binary.LittleEndian.PutUint16(typeSpec[0:2], chunkTableTypeSpec)
	binary.LittleEndian.PutUint16(typeSpec[2:4], typeSpecHdrSize)
	binary.LittleEndian.PutUint32(typeSpec[4:8], uint32(len(typeSpec)))
	typeSpec[8] = 1 // typeID = 1

	// type chunk: minimal ResTable_type with 1 entry
	// Layout: chunk_hdr(8) + body(at least 12 + cfg_size)
	// ResTable_type body: typeID(1), flags(1), reserved(2), entryCount(4), entriesStart(4), config(?)
	// Minimal config is 32 bytes (header size field in first 4 bytes, rest padding)
	const minCfgSize = 32
	const typeHdrSize = 8 + 1 + 1 + 2 + 4 + 4 + minCfgSize // = 52
	// 1 entry offset table: 4 bytes (offset=0)
	// entry data: flags(2)+keyIdx(4)=8 + Res_value(8) = 8 bytes entry + 8 bytes value = 16
	const entryOff = 0
	const entryData = 8 + 8 // entry header + Res_value
	typeChunkSize := typeHdrSize + 4 + entryData
	typeChunk := make([]byte, typeChunkSize)
	binary.LittleEndian.PutUint16(typeChunk[0:2], chunkTableType)
	binary.LittleEndian.PutUint16(typeChunk[2:4], uint16(typeHdrSize))
	binary.LittleEndian.PutUint32(typeChunk[4:8], uint32(typeChunkSize))
	typeChunk[8] = 1                                                       // typeID
	typeChunk[9] = 0                                                       // flags
	typeChunk[10] = 0                                                      // reserved[0]
	typeChunk[11] = 0                                                      // reserved[1]
	binary.LittleEndian.PutUint32(typeChunk[12:16], 1)                     // entryCount
	binary.LittleEndian.PutUint32(typeChunk[16:20], uint32(typeHdrSize+4)) // entriesStart
	// Minimal ResTable_config: first 4 bytes = size (32)
	binary.LittleEndian.PutUint32(typeChunk[20:24], minCfgSize)
	// Entry offset table (at typeHdrSize): offset 0
	binary.LittleEndian.PutUint32(typeChunk[typeHdrSize:], 0) // entry 0 at offset 0

	// Entry: simple value at entriesStart
	entryBase := typeHdrSize + 4
	binary.LittleEndian.PutUint16(typeChunk[entryBase:], 8)   // size = 8 (simple entry)
	binary.LittleEndian.PutUint16(typeChunk[entryBase+2:], 0) // flags = 0
	binary.LittleEndian.PutUint32(typeChunk[entryBase+4:], 0) // keyIdx = 0 → "app_name"
	// Res_value: size=8, res0=0, type=typeIntDec, data=42
	binary.LittleEndian.PutUint16(typeChunk[entryBase+8:], 8)   // value size
	typeChunk[entryBase+10] = 0                                 // res0
	typeChunk[entryBase+11] = typeIntDec                        // value type
	binary.LittleEndian.PutUint32(typeChunk[entryBase+12:], 42) // value data

	// Package header body: id(4) + name(256) + typeStringsOff(4) + lastPublicType(4) +
	//                      keyStringsOff(4) + lastPublicKey(4) = 276 bytes
	const pkgBodySize = 4 + 256 + 4 + 4 + 4 + 4 // 276
	const pkgHdrTotal = 8 + pkgBodySize         // 284

	typeStringsOff := pkgHdrTotal
	keyStringsOff := typeStringsOff + len(typePool)
	subChunksOff := keyStringsOff + len(keyPool)
	totalSize := subChunksOff + len(typeSpec) + len(typeChunk)

	pkg := make([]byte, totalSize)
	binary.LittleEndian.PutUint16(pkg[0:2], chunkTablePackage)
	binary.LittleEndian.PutUint16(pkg[2:4], uint16(pkgHdrTotal))
	binary.LittleEndian.PutUint32(pkg[4:8], uint32(totalSize))
	binary.LittleEndian.PutUint32(pkg[8:12], 0x7f) // packageID
	// name (UTF-16LE "app", padded to 256 bytes)
	pkg[12] = 'a'
	pkg[14] = 'p'
	pkg[16] = 'p'
	binary.LittleEndian.PutUint32(pkg[8+4+256:], uint32(typeStringsOff))
	// lastPublicType at 8+4+256+4
	binary.LittleEndian.PutUint32(pkg[8+4+256+8:], uint32(keyStringsOff))

	copy(pkg[typeStringsOff:], typePool)
	copy(pkg[keyStringsOff:], keyPool)
	copy(pkg[subChunksOff:], typeSpec)
	copy(pkg[subChunksOff+len(typeSpec):], typeChunk)

	return pkg
}

func TestParseTablePackage_Minimal(t *testing.T) {
	chunk := buildTablePackageChunk(t)
	pkg, err := parseTablePackage(chunk, nil)
	if err != nil {
		t.Fatalf("parseTablePackage: %v", err)
	}
	if pkg.ID != 0x7f {
		t.Errorf("pkg.ID = 0x%x, want 0x7f", pkg.ID)
	}
}

func TestParseTablePackage_TooSmall(t *testing.T) {
	_, err := parseTablePackage(make([]byte, 10), nil)
	if err == nil {
		t.Error("expected error for too-small chunk")
	}
}

func TestParseTableEntry_SimpleValue(t *testing.T) {
	keyPool := &stringPool{entries: []string{"my_key"}}
	// Entry: size=8, flags=0, keyIdx=0, followed by Res_value(size=8,res0=0,type=intDec,data=99)
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], 8)    // entry size
	binary.LittleEndian.PutUint16(buf[2:4], 0)    // flags (simple, not compact)
	binary.LittleEndian.PutUint32(buf[4:8], 0)    // keyIdx = 0
	binary.LittleEndian.PutUint16(buf[8:10], 8)   // Res_value size
	buf[10] = 0                                   // res0
	buf[11] = typeIntDec                          // type
	binary.LittleEndian.PutUint32(buf[12:16], 99) // data

	name, val, isBag, err := parseTableEntry(buf, keyPool)
	if err != nil {
		t.Fatalf("parseTableEntry: %v", err)
	}
	if name != "my_key" {
		t.Errorf("name=%q, want my_key", name)
	}
	if val.String != "99" {
		t.Errorf("val=%q, want 99", val.String)
	}
	if isBag {
		t.Error("should not be bag")
	}
}

func TestParseTableEntry_TooShort(t *testing.T) {
	_, _, _, err := parseTableEntry([]byte{1, 2, 3}, nil)
	if err == nil {
		t.Error("expected error for too-short buffer")
	}
}

func TestParseTableEntry_ComplexBag(t *testing.T) {
	keyPool := &stringPool{entries: []string{"style_key"}}
	// Complex entry: size=16 (so Res_value skipped), flags=entryFlagComplex,
	// keyIdx=0, parent=0, count=1 + one (nameID, Res_value) pair
	const entrySize = 16
	buf := make([]byte, entrySize+12)
	binary.LittleEndian.PutUint16(buf[0:2], entrySize) // size
	binary.LittleEndian.PutUint16(buf[2:4], entryFlagComplex)
	binary.LittleEndian.PutUint32(buf[4:8], 0)   // keyIdx
	binary.LittleEndian.PutUint32(buf[8:12], 0)  // parent = 0
	binary.LittleEndian.PutUint32(buf[12:16], 1) // count = 1
	// Complex value item: nameID(4) + Res_value(size=8, res0=0, type, data)
	binary.LittleEndian.PutUint32(buf[16:20], 0x01010003) // nameID
	binary.LittleEndian.PutUint16(buf[20:22], 8)          // res_value size (at offset 4 within item)
	buf[23] = typeIntBoolean
	binary.LittleEndian.PutUint32(buf[24:28], 1) // data=true

	name, val, isBag, err := parseTableEntry(buf, keyPool)
	if err != nil {
		t.Fatalf("complex entry: %v", err)
	}
	if name != "style_key" {
		t.Errorf("name=%q", name)
	}
	if !isBag {
		t.Error("expected isBag=true")
	}
	if len(val.ComplexValues) != 1 {
		t.Errorf("expected 1 complex value, got %d", len(val.ComplexValues))
	}
}

func TestParseTableEntry_CompactEntry(t *testing.T) {
	keyPool := &stringPool{entries: []string{"compact_key"}}
	// Compact entry: entryFlagCompact set in flags
	// In compact form: size field holds the key index, flags>>8 = value type
	// The entry is 8 bytes: size(2)+flags(2)+data(4)
	const keyIndex = 0
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(keyIndex)) // key idx in size field
	flags := uint16(entryFlagCompact) | (uint16(typeIntDec) << 8)
	binary.LittleEndian.PutUint16(buf[2:4], flags)
	binary.LittleEndian.PutUint32(buf[4:8], 123) // value data

	name, val, isBag, err := parseTableEntry(buf, keyPool)
	if err != nil {
		t.Fatalf("compact entry: %v", err)
	}
	if name != "compact_key" {
		t.Errorf("name=%q", name)
	}
	if isBag {
		t.Error("compact entry should not be bag")
	}
	if val.String != "123" {
		t.Errorf("val=%q, want 123", val.String)
	}
}

func TestParseTableEntry_NoEntryKey(t *testing.T) {
	// keyIdx == noEntry (0xFFFFFFFF)
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], 8)
	binary.LittleEndian.PutUint16(buf[2:4], 0) // not compact
	binary.LittleEndian.PutUint32(buf[4:8], noEntry)
	_, _, _, err := parseTableEntry(buf, &stringPool{entries: []string{}})
	if err == nil {
		t.Error("expected error for no-entry key")
	}
}

func TestParseTableLibrary_Basic(t *testing.T) {
	// chunk[0:8] = chunk header, chunk[8:12] = count=1
	// then 1 entry: pid(4) + name(256 bytes UTF-16LE)
	const entrySize = 4 + 256
	total := 12 + entrySize
	buf := make([]byte, total)
	binary.LittleEndian.PutUint16(buf[0:2], chunkTableLibrary)
	binary.LittleEndian.PutUint16(buf[2:4], 8)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(total))
	binary.LittleEndian.PutUint32(buf[8:12], 1)     // count=1
	binary.LittleEndian.PutUint32(buf[12:16], 0x01) // pid=1 (android)
	// name in UTF-16LE: "android\0"
	name := "android"
	for i, c := range name {
		buf[16+i*2] = byte(c)
	}

	libs := parseTableLibrary(buf)
	if len(libs) != 1 {
		t.Fatalf("expected 1 library, got %d", len(libs))
	}
	if libs[0].PackageID != 1 {
		t.Errorf("packageID=%d", libs[0].PackageID)
	}
	if libs[0].Name != "android" {
		t.Errorf("name=%q", libs[0].Name)
	}
}

func TestParseTableLibrary_TooSmall(t *testing.T) {
	libs := parseTableLibrary(make([]byte, 8))
	if libs != nil {
		t.Error("expected nil for too-small chunk")
	}
}

func TestParseTableLibrary_TruncatedEntries(t *testing.T) {
	// count=5 but buffer only has room for 0 entries
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[8:12], 5) // count=5, but no entry data
	libs := parseTableLibrary(buf)
	if len(libs) != 0 {
		t.Errorf("expected 0 libs for truncated, got %d", len(libs))
	}
}

// ---------------------------------------------------------------------------
// arsc.go — decodeUTF16 direct tests
// ---------------------------------------------------------------------------

func TestDecodeUTF16_ASCII(t *testing.T) {
	// Basic ASCII → no surrogates
	units := []uint16{'H', 'e', 'l', 'l', 'o'}
	runes := decodeUTF16(units)
	got := string(runes)
	if got != "Hello" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeUTF16_SurrogatePair(t *testing.T) {
	// U+1F600 (😀) as surrogate pair: D83D DE00
	units := []uint16{0xD83D, 0xDE00}
	runes := decodeUTF16(units)
	got := string(runes)
	if got != "\U0001F600" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeUTF16_HighSurrogateWithoutLow(t *testing.T) {
	// High surrogate at end of slice — no low follows
	units := []uint16{0xD83D}
	runes := decodeUTF16(units)
	if len(runes) != 1 || runes[0] != '�' {
		t.Errorf("expected replacement char, got %v", runes)
	}
}

func TestDecodeUTF16_HighSurrogateWrongLow(t *testing.T) {
	// High surrogate followed by non-low-surrogate
	units := []uint16{0xD83D, 0x0041} // 'A' is not a low surrogate
	runes := decodeUTF16(units)
	// Should produce replacement + 'A'
	if len(runes) != 2 || runes[0] != '�' || runes[1] != 'A' {
		t.Errorf("got %v", runes)
	}
}

func TestDecodeUTF16_LoneSurrogateLow(t *testing.T) {
	// Low surrogate without preceding high → replacement
	units := []uint16{0xDC00}
	runes := decodeUTF16(units)
	if len(runes) != 1 || runes[0] != '�' {
		t.Errorf("expected replacement, got %v", runes)
	}
}

func TestDecodeUTF16_BMP(t *testing.T) {
	// Characters in the BMP range (not surrogates): e.g. U+4E2D (中)
	units := []uint16{0x4E2D}
	runes := decodeUTF16(units)
	if len(runes) != 1 || runes[0] != '中' {
		t.Errorf("got %v", runes)
	}
}

// ---------------------------------------------------------------------------
// arsc.go — resolveStringRefs: complex values
// ---------------------------------------------------------------------------

func TestResolveStringRefs_ComplexValues(t *testing.T) {
	table := &ResourceTable{
		GlobalStrings: []string{"one", "two", "three"},
		Packages: []ResourcePackage{
			{
				ID:   0x7f,
				Name: "test",
				Types: []ResourceType{
					{
						ID:   1,
						Name: "array",
						Entries: []ResourceEntry{
							{
								ID:   0,
								Name: "items",
								Values: []ConfigValue{
									{
										Config: "default",
										Value:  "strpool:0",
										ComplexValues: []ComplexValue{
											{NameID: 0, Value: "strpool:1"},
											{NameID: 1, Value: "strpool:2"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	table.resolveStringRefs()

	val := table.Packages[0].Types[0].Entries[0].Values[0]
	if val.Value != "one" {
		t.Errorf("simple val=%q, want one", val.Value)
	}
	if val.ComplexValues[0].Value != "two" {
		t.Errorf("complex[0]=%q, want two", val.ComplexValues[0].Value)
	}
	if val.ComplexValues[1].Value != "three" {
		t.Errorf("complex[1]=%q, want three", val.ComplexValues[1].Value)
	}
}

func TestResolveStringRefs_OutOfBounds(t *testing.T) {
	// strpool:99 with GlobalStrings of len 1 → should resolve to ""
	table := &ResourceTable{
		GlobalStrings: []string{"only"},
		Packages: []ResourcePackage{
			{
				ID: 0x7f,
				Types: []ResourceType{
					{
						ID: 1,
						Entries: []ResourceEntry{
							{
								ID: 0,
								Values: []ConfigValue{
									{Value: "strpool:99"},
								},
							},
						},
					},
				},
			},
		},
	}
	table.resolveStringRefs()
	val := table.Packages[0].Types[0].Entries[0].Values[0].Value
	if val != "" {
		t.Errorf("expected empty for OOB strpool, got %q", val)
	}
}

func TestResolveStringRefs_NonStrpool(t *testing.T) {
	// Values not starting with "strpool:" should be left unchanged
	table := &ResourceTable{
		GlobalStrings: []string{"something"},
		Packages: []ResourcePackage{
			{
				ID: 0x7f,
				Types: []ResourceType{
					{
						ID: 1,
						Entries: []ResourceEntry{
							{
								ID: 0,
								Values: []ConfigValue{
									{Value: "@0x7f010000"},
								},
							},
						},
					},
				},
			},
		},
	}
	table.resolveStringRefs()
	val := table.Packages[0].Types[0].Entries[0].Values[0].Value
	if val != "@0x7f010000" {
		t.Errorf("non-strpool value should be unchanged, got %q", val)
	}
}

// ---------------------------------------------------------------------------
// strings.go — containsSurrogateTriplet
// ---------------------------------------------------------------------------

func TestContainsSurrogateTriplet_HighSurrogate(t *testing.T) {
	// U+D800 encoded as 3-byte: ED A0 80
	b := []byte{0xED, 0xA0, 0x80}
	if !containsSurrogateTriplet(b) {
		t.Error("expected surrogate triplet for ED A0 80")
	}
}

func TestContainsSurrogateTriplet_LowSurrogate(t *testing.T) {
	// U+DC00 encoded as 3-byte: ED B0 80
	b := []byte{0xED, 0xB0, 0x80}
	if !containsSurrogateTriplet(b) {
		t.Error("expected surrogate triplet for ED B0 80")
	}
}

func TestContainsSurrogateTriplet_NormalUTF8_3byte(t *testing.T) {
	// U+4E2D (中) = E4 B8 AD — not a surrogate
	b := []byte{0xE4, 0xB8, 0xAD}
	if containsSurrogateTriplet(b) {
		t.Error("U+4E2D should not be detected as surrogate")
	}
}

func TestContainsSurrogateTriplet_TwoByteSeq(t *testing.T) {
	// 2-byte sequence should not trigger surrogate detection
	b := []byte{0xC3, 0xA9} // é
	if containsSurrogateTriplet(b) {
		t.Error("2-byte seq should not be detected as surrogate")
	}
}

func TestContainsSurrogateTriplet_FourByte(t *testing.T) {
	// 4-byte sequence (U+1F600): F0 9F 98 80
	b := []byte{0xF0, 0x9F, 0x98, 0x80}
	if containsSurrogateTriplet(b) {
		t.Error("4-byte sequence should not be detected as surrogate")
	}
}

func TestContainsSurrogateTriplet_Empty(t *testing.T) {
	if containsSurrogateTriplet([]byte{}) {
		t.Error("empty should return false")
	}
}

func TestContainsSurrogateTriplet_ContinuationByte(t *testing.T) {
	// Stray continuation byte at start: should not panic
	b := []byte{0x80, 0xED, 0xA0, 0x80}
	// Contains a surrogate triplet at offset 1
	if !containsSurrogateTriplet(b) {
		t.Error("expected surrogate triplet after stray continuation byte")
	}
}

func TestContainsSurrogateTriplet_TruncatedThreeByteSeq(t *testing.T) {
	// 3-byte seq start but only 2 bytes available
	b := []byte{0xED, 0xA0} // truncated, only 2 bytes, loop check i+2<len exits
	// The loop condition is i+2 < len(b) for the 3-byte check: 0+2 < 2 is false
	if containsSurrogateTriplet(b) {
		t.Error("truncated 3-byte seq should not detect surrogate")
	}
}

// ---------------------------------------------------------------------------
// decoder.go — lookupPrefix and attrName (indirect via Decoder)
// ---------------------------------------------------------------------------

func TestDecoder_LookupPrefix_Empty(t *testing.T) {
	d := &Decoder{
		pool:    nil,
		nsStack: newNamespaceStack(),
	}
	got := d.lookupPrefix("http://example.com")
	if got != "" {
		t.Errorf("lookupPrefix with nil pool should be empty, got %q", got)
	}
}

func TestDecoder_LookupPrefix_EmptyURI(t *testing.T) {
	d := &Decoder{
		pool:    &stringPool{entries: []string{"android", "http://schemas.android.com/apk/res/android"}},
		nsStack: newNamespaceStack(),
	}
	got := d.lookupPrefix("")
	if got != "" {
		t.Errorf("empty URI should return empty, got %q", got)
	}
}

func TestDecoder_LookupPrefix_Found(t *testing.T) {
	pool := &stringPool{entries: []string{"android", "http://schemas.android.com/apk/res/android"}}
	d := &Decoder{
		pool:    pool,
		nsStack: newNamespaceStack(),
	}
	// Push a namespace: prefix=0 ("android"), uri=1 ("http://...")
	d.nsStack.pushNamespace(0, 1)
	got := d.lookupPrefix("http://schemas.android.com/apk/res/android")
	if got != "android" {
		t.Errorf("expected android prefix, got %q", got)
	}
}

func TestDecoder_LookupPrefix_NotFound(t *testing.T) {
	pool := &stringPool{entries: []string{"android", "http://schemas.android.com/apk/res/android"}}
	d := &Decoder{
		pool:    pool,
		nsStack: newNamespaceStack(),
	}
	got := d.lookupPrefix("http://other.com")
	if got != "" {
		t.Errorf("should return empty for unknown URI, got %q", got)
	}
}

func TestDecoder_AttrName_FromPool(t *testing.T) {
	pool := &stringPool{entries: []string{"myattr", "otherattr"}}
	d := &Decoder{
		pool:   pool,
		resMap: nil,
	}
	got := d.attrName(0)
	if got != "myattr" {
		t.Errorf("expected myattr, got %q", got)
	}
}

func TestDecoder_AttrName_EmptyInPool_FallbackResMap(t *testing.T) {
	// Pool has empty string at idx 0 → look in resMap
	pool := &stringPool{entries: []string{""}}
	d := &Decoder{
		pool:   pool,
		resMap: []uint32{0x0101000f}, // "debuggable"
	}
	got := d.attrName(0)
	if got != "debuggable" {
		t.Errorf("expected debuggable, got %q", got)
	}
}

func TestDecoder_AttrName_UnknownResMapID(t *testing.T) {
	pool := &stringPool{entries: []string{""}}
	d := &Decoder{
		pool:   pool,
		resMap: []uint32{0xdeadbeef}, // unknown ID
	}
	got := d.attrName(0)
	if got != "attr_deadbeef" {
		t.Errorf("expected attr_deadbeef, got %q", got)
	}
}

func TestDecoder_AttrName_OutOfBothRanges(t *testing.T) {
	// idx out of pool and resMap
	pool := &stringPool{entries: []string{"a"}}
	d := &Decoder{
		pool:   pool,
		resMap: []uint32{0x01010003},
	}
	got := d.attrName(99)
	if got != SentinelNoString {
		t.Errorf("expected sentinel, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// framework.go
// ---------------------------------------------------------------------------

func TestLoadFrameworkAPK_NotAZip(t *testing.T) {
	// Create a temp file that is not a zip
	tmp := t.TempDir() + "/not_a_zip.apk"
	if err := os.WriteFile(tmp, []byte("this is not a zip"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFrameworkAPK(tmp)
	if err == nil {
		t.Error("expected error for non-zip file")
	}
}

func TestLoadFrameworkAPK_ZipWithoutARSC(t *testing.T) {
	// Create a valid zip without resources.arsc
	import_buf := makeZipWithoutARSC(t)
	tmp := t.TempDir() + "/no_arsc.apk"
	if err := os.WriteFile(tmp, import_buf, 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFrameworkAPK(tmp)
	if err == nil {
		t.Error("expected error when resources.arsc is missing from zip")
	}
}

func TestAutoLoadFramework_NoSDK(t *testing.T) {
	// Without ANDROID_HOME or ANDROID_SDK_ROOT set, should return nil gracefully
	t.Setenv("ANDROID_HOME", "")
	t.Setenv("ANDROID_SDK_ROOT", "")
	fr := AutoLoadFramework()
	if fr != nil {
		t.Error("expected nil when no SDK env vars set")
	}
}

func TestAutoLoadFramework_BadSDKPath(t *testing.T) {
	// Point to a non-existent directory
	t.Setenv("ANDROID_HOME", "/no/such/sdk/path/xyz")
	t.Setenv("ANDROID_SDK_ROOT", "")
	fr := AutoLoadFramework()
	if fr != nil {
		t.Error("expected nil for bad SDK path")
	}
}

func TestFrameworkResolver_ResolveName_WithTable(t *testing.T) {
	// FrameworkResolver with a real (simple) table
	fr := &FrameworkResolver{table: buildSimpleResourceTable()}
	// buildSimpleResourceTable has pkg=0x7f, type=1, entry=0 → "@string/app_name"
	got := fr.ResolveName(0x7f010000)
	if got != "@string/app_name" {
		t.Errorf("got %q", got)
	}
}

func TestFrameworkResolver_ResolveName_Unknown(t *testing.T) {
	fr := &FrameworkResolver{table: buildSimpleResourceTable()}
	got := fr.ResolveName(0x00000000)
	if got != "" {
		t.Errorf("expected empty for unknown ID, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// resolve.go — resolveComponentRefs and resolveRefString more paths
// ---------------------------------------------------------------------------

func TestResolveComponentRefs_PermissionRef(t *testing.T) {
	table := buildSimpleResourceTable()
	c := &Component{
		Name:       "MyActivity",
		Permission: "@0x7f010000", // resolves to "MyApp"
		IntentFilts: []IntentFilter{
			{
				DataScheme: []string{"@0x7f010000"},
				DataHost:   []string{"@0x7f010001"},
			},
		},
	}
	resolveComponentRefs(c, table)
	if c.Permission != "MyApp" {
		t.Errorf("permission=%q, want MyApp", c.Permission)
	}
	if c.IntentFilts[0].DataScheme[0] != "MyApp" {
		t.Errorf("DataScheme[0]=%q", c.IntentFilts[0].DataScheme[0])
	}
}

func TestResolveComponentRefs_NilSafety(t *testing.T) {
	// Should not panic when strings are non-refs
	c := &Component{
		Name:       "Activity",
		Permission: "android.permission.INTERNET", // not a ref
	}
	resolveComponentRefs(c, &ResourceTable{})
	if c.Permission != "android.permission.INTERNET" {
		t.Errorf("non-ref permission changed: %q", c.Permission)
	}
}

func TestResolveComponentRefs_NilPointer(t *testing.T) {
	// Passing nil strings should not panic (resolveString handles nil pointer)
	c := &Component{
		Name:       "Activity",
		Permission: "",
	}
	resolveComponentRefs(c, buildSimpleResourceTable())
	if c.Permission != "" {
		t.Errorf("expected empty, got %q", c.Permission)
	}
}

func TestResolveRefString_FallsBackToHexWhenUnresolved(t *testing.T) {
	// ID not in the table → returns @0x formatted hex
	table := &ResourceTable{}
	got := resolveRefString("@0x7f010000", table)
	if got != "@0x7f010000" {
		t.Errorf("expected @0x7f010000, got %q", got)
	}
}

func TestResolveRefString_ResolvesViaName(t *testing.T) {
	table := buildSimpleResourceTable()
	// 0x7f010001 = "greeting", has default "Hello" but stays a reference.
	got := resolveRefString("@0x7f010001", table)
	if got != "@string/greeting" {
		t.Errorf("expected @string/greeting, got %q", got)
	}
}

func TestResolveRefString_KeepsStringValuesOutOfXML(t *testing.T) {
	// The reference must survive even when its value contains XML characters.
	table := &ResourceTable{
		Packages: []ResourcePackage{
			{
				ID:      0x7f,
				Name:    "test",
				TypeIDs: map[string]uint32{"string": 1},
				Types: []ResourceType{
					{
						ID:   1,
						Name: "string",
						Entries: []ResourceEntry{
							{
								ID:   0,
								Name: "url",
								Values: []ConfigValue{
									{Config: "default", Value: `http://a.com?x=1&y=2`},
								},
							},
						},
					},
				},
			},
		},
	}
	got := resolveRefString("@0x7f010000", table)
	if got != "@string/url" {
		t.Errorf("expected a resource reference, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Full ParseARSC with package chunk
// ---------------------------------------------------------------------------

func TestParseARSC_WithPackageChunk(t *testing.T) {
	pkgChunk := buildTablePackageChunk(t)

	// Build global string pool
	globalPool := buildEmptyStringPoolChunk()

	// Build the full RES_TABLE
	totalSize := uint32(12 + len(globalPool) + len(pkgChunk))
	buf := make([]byte, totalSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkTable)
	binary.LittleEndian.PutUint16(buf[2:4], 12)
	binary.LittleEndian.PutUint32(buf[4:8], totalSize)
	binary.LittleEndian.PutUint32(buf[8:12], 1) // packageCount=1
	copy(buf[12:], globalPool)
	copy(buf[12+len(globalPool):], pkgChunk)

	table, err := ParseARSC(buf)
	if err != nil {
		t.Fatalf("ParseARSC with package: %v", err)
	}
	if len(table.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(table.Packages))
	}
	if table.Packages[0].ID != 0x7f {
		t.Errorf("pkg ID=%x", table.Packages[0].ID)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeZipWithoutARSC creates a minimal valid ZIP archive without resources.arsc.
func makeZipWithoutARSC(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	zipPath := dir + "/test.zip"

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	w := archivezip.NewWriter(f)
	fw, err := w.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("<?xml version=1.0?>"))
	w.Close()
	f.Close()

	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
