package axml

import (
	"encoding/binary"
	"strings"
	"testing"
)

func overlayManifest(t *testing.T, orig []byte, text string) []byte {
	t.Helper()
	out, err := OverlayAXML(orig, []byte(text), nil)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	return out
}

func decodePerms(t *testing.T, bin []byte) *Manifest {
	t.Helper()
	m, err := Decode(bin)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestOverlayPermissionChange(t *testing.T) {
	orig := MinimalManifestXML()
	text := `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><uses-permission android:name="android.permission.CAMERA"/></manifest>`
	m := decodePerms(t, overlayManifest(t, orig, text))
	if len(m.Permissions) != 1 || m.Permissions[0] != "android.permission.CAMERA" {
		t.Fatalf("permissions = %v", m.Permissions)
	}
	if m.Package != "com.example" {
		t.Fatalf("package = %q", m.Package)
	}
}

func TestOverlayAddPermission(t *testing.T) {
	orig := MinimalManifestXML()
	text := `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.CAMERA"/></manifest>`
	m := decodePerms(t, overlayManifest(t, orig, text))
	if len(m.Permissions) != 2 {
		t.Fatalf("permissions = %v", m.Permissions)
	}
}

func TestOverlayPackageRename(t *testing.T) {
	orig := MinimalManifestXML()
	text := `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.renamed"><uses-permission android:name="android.permission.INTERNET"/></manifest>`
	m := decodePerms(t, overlayManifest(t, orig, text))
	if m.Package != "com.renamed" {
		t.Fatalf("package = %q", m.Package)
	}
}

func TestOverlayUnchangedKeepsBytes(t *testing.T) {
	orig := MinimalManifestXML()
	m0, err := Decode(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Re-encode the decoded text: values must survive.
	out, err := OverlayAXML(orig, m0.XMLBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Package != m0.Package || len(m1.Permissions) != len(m0.Permissions) || m1.Permissions[0] != m0.Permissions[0] {
		t.Fatalf("round-trip changed manifest: %+v vs %+v", m1, m0)
	}
}

func TestOverlayBoolAndInt(t *testing.T) {
	orig := MinimalManifestXML()
	step1 := `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><uses-permission android:name="android.permission.INTERNET"/><application android:label="App" android:debuggable="true"/><uses-sdk android:minSdkVersion="21"/></manifest>`
	b1 := overlayManifest(t, orig, step1)
	m1 := decodePerms(t, b1)
	if !m1.Application.Debuggable {
		t.Fatalf("debuggable not set: %+v", m1.Application)
	}
	if m1.Application.Label != "App" {
		t.Fatalf("label = %q", m1.Application.Label)
	}
	if m1.MinSDK != 21 {
		t.Fatalf("minSdk = %d", m1.MinSDK)
	}
	// Flip bool + bump int.
	m1t, err := Decode(b1)
	if err != nil {
		t.Fatal(err)
	}
	step2 := strings.Replace(string(m1t.XMLBytes), `android:debuggable="true"`, `android:debuggable="false"`, 1)
	step2 = strings.Replace(step2, `android:minSdkVersion="21"`, `android:minSdkVersion="23"`, 1)
	m2 := decodePerms(t, overlayManifest(t, b1, step2))
	if m2.Application.Debuggable {
		t.Fatal("debuggable not flipped")
	}
	if m2.MinSDK != 23 {
		t.Fatalf("minSdk = %d", m2.MinSDK)
	}
}

func TestOverlayRejectsRename(t *testing.T) {
	orig := MinimalManifestXML()
	text := `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><permission android:name="android.permission.MINE"/></manifest>`
	if _, err := OverlayAXML(orig, []byte(text), nil); err == nil {
		t.Fatal("expected error for unmatched element")
	} else if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ── ARSC entry edits ─────────────────────────────────────────────────────────

func buildStringTable(t *testing.T, global []string, keys []string, entries []testEntry) []byte {
	t.Helper()
	gpool := buildStringPoolChunkWithEntries(global)
	typePool := buildStringPoolChunkWithEntries([]string{"string"})
	keyPool := buildStringPoolChunkWithEntries(keys)
	// One type chunk per config? Single config (default) with N entries.
	const minCfgSize = 32
	const typeHdrSize = 8 + 1 + 1 + 2 + 4 + 4 + minCfgSize
	n := len(entries)
	offTable := make([]byte, 4*n)
	entryData := []byte{}
	off := uint32(0)
	for i, e := range entries {
		binary.LittleEndian.PutUint32(offTable[i*4:], off)
		base := len(entryData)
		entryData = append(entryData, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.LittleEndian.PutUint16(entryData[base:], 8)
		binary.LittleEndian.PutUint16(entryData[base+2:], 0)
		binary.LittleEndian.PutUint32(entryData[base+4:], uint32(e.keyIdx))
		binary.LittleEndian.PutUint16(entryData[base+8:], 8)
		entryData[base+10] = 0
		entryData[base+11] = e.typ
		binary.LittleEndian.PutUint32(entryData[base+12:], e.data)
		off += 16
		_ = base
	}
	typeChunkSize := typeHdrSize + len(offTable) + len(entryData)
	typeChunk := make([]byte, typeChunkSize)
	binary.LittleEndian.PutUint16(typeChunk[0:2], chunkTableType)
	binary.LittleEndian.PutUint16(typeChunk[2:4], uint16(typeHdrSize))
	binary.LittleEndian.PutUint32(typeChunk[4:8], uint32(typeChunkSize))
	typeChunk[8] = 1
	binary.LittleEndian.PutUint32(typeChunk[12:16], uint32(n))
	binary.LittleEndian.PutUint32(typeChunk[16:20], uint32(typeHdrSize+len(offTable)))
	binary.LittleEndian.PutUint32(typeChunk[20:24], minCfgSize)
	copy(typeChunk[typeHdrSize:], offTable)
	copy(typeChunk[typeHdrSize+len(offTable):], entryData)
	// typeSpec
	typeSpec := make([]byte, 20)
	binary.LittleEndian.PutUint16(typeSpec[0:2], chunkTableTypeSpec)
	binary.LittleEndian.PutUint16(typeSpec[2:4], 16)
	binary.LittleEndian.PutUint32(typeSpec[4:8], 20)
	typeSpec[8] = 1
	// package
	const pkgHdrTotal = 8 + 4 + 256 + 4 + 4 + 4 + 4
	typeStringsOff := pkgHdrTotal
	keyStringsOff := typeStringsOff + len(typePool)
	subOff := keyStringsOff + len(keyPool)
	total := subOff + len(typeSpec) + len(typeChunk)
	pkg := make([]byte, total)
	binary.LittleEndian.PutUint16(pkg[0:2], chunkTablePackage)
	binary.LittleEndian.PutUint16(pkg[2:4], uint16(pkgHdrTotal))
	binary.LittleEndian.PutUint32(pkg[4:8], uint32(total))
	binary.LittleEndian.PutUint32(pkg[8:12], 0x7f)
	copy(pkg[12:], []byte("a\x00p\x00p\x00"))
	binary.LittleEndian.PutUint32(pkg[8+4+256:], uint32(typeStringsOff))
	binary.LittleEndian.PutUint32(pkg[8+4+256+8:], uint32(keyStringsOff))
	copy(pkg[typeStringsOff:], typePool)
	copy(pkg[keyStringsOff:], keyPool)
	copy(pkg[subOff:], typeSpec)
	copy(pkg[subOff+len(typeSpec):], typeChunk)
	// root
	rootSize := 12 + len(gpool) + len(pkg)
	root := make([]byte, rootSize)
	binary.LittleEndian.PutUint16(root[0:2], chunkTable)
	binary.LittleEndian.PutUint16(root[2:4], 12)
	binary.LittleEndian.PutUint32(root[4:8], uint32(rootSize))
	binary.LittleEndian.PutUint32(root[8:12], 1)
	copy(root[12:], gpool)
	copy(root[12+len(gpool):], pkg)
	return root
}

type testEntry struct {
	keyIdx int
	typ    uint8
	data   uint32
}

func arscString(t *testing.T, data []byte, name string) string {
	t.Helper()
	table, err := ParseARSC(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range table.Packages {
		for _, ty := range p.Types {
			if ty.Name != "string" {
				continue
			}
			for _, e := range ty.Entries {
				if e.Name == name {
					for _, v := range e.Values {
						if v.Config == "default" || v.Config == "" {
							return v.Value
						}
					}
				}
			}
		}
	}
	t.Fatalf("entry %s not found", name)
	return ""
}

func TestPatchARSCEntryString(t *testing.T) {
	data := buildStringTable(t, []string{"Hello"}, []string{"app_name"}, []testEntry{{0, typeString, 0}})
	out, err := PatchARSCEntry(data, "string", "app_name", "default", "World")
	if err != nil {
		t.Fatal(err)
	}
	if got := arscString(t, out, "app_name"); got != "World" {
		t.Fatalf("value = %q", got)
	}
}

func TestPatchARSCEntrySharedSplit(t *testing.T) {
	// Two entries share pool slot 0 ("Hello"); edit one.
	data := buildStringTable(t, []string{"Hello"}, []string{"app_name", "app_title"},
		[]testEntry{{0, typeString, 0}, {1, typeString, 0}})
	out, err := PatchARSCEntry(data, "string", "app_name", "default", "World")
	if err != nil {
		t.Fatal(err)
	}
	if got := arscString(t, out, "app_name"); got != "World" {
		t.Fatalf("app_name = %q", got)
	}
	if got := arscString(t, out, "app_title"); got != "Hello" {
		t.Fatalf("app_title clobbered = %q", got)
	}
}

func TestPatchARSCEntryInt(t *testing.T) {
	data := buildStringTable(t, []string{}, []string{"num"}, []testEntry{{0, typeIntDec, 42}})
	// Fix type name: builder uses "string" type; patch int via raw walker needs
	// matching type name — rebuild uses type pool ["string"], so address as such.
	out, err := PatchARSCEntries(data, []ARSCEdit{{Type: "string", Name: "num", Config: "default", NewValue: "43"}})
	if err != nil {
		t.Fatal(err)
	}
	table, err := ParseARSC(out)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range table.Packages {
		for _, ty := range p.Types {
			for _, e := range ty.Entries {
				if e.Name == "num" {
					found = true
					if e.Values[0].Value != "43" {
						t.Fatalf("value = %q", e.Values[0].Value)
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("entry missing")
	}
}
