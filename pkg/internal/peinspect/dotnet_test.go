package peinspect

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildMinimalDotNetPE synthesizes a tiny valid CLI image: one module, two
// TypeDefs, one MethodDef entry point, one Assembly + one assembly-level
// TargetFrameworkAttribute. It exercises the full metadata chain without
// depending on external binaries.
func buildMinimalDotNetPE(t *testing.T) []byte {
	t.Helper()
	put16 := func(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	put32 := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

	// #Strings heap with tracked offsets.
	strs := []byte{0}
	at := map[string]uint32{}
	addStr := func(s string) {
		at[s] = uint32(len(strs))
		strs = append(strs, s...)
		strs = append(strs, 0)
	}
	for _, s := range []string{"test.exe", "<Module>", "Program", "NS", "Main", "TerrariaTest", "TargetFrameworkAttribute", "System.Runtime.Versioning", ".ctor"} {
		addStr(s)
	}

	// #Blob heap: [0]=empty, [sigOff]=method sig, [mrSigOff]=memberref sig,
	// [attrOff]=custom attribute value.
	blob := []byte{0x00}
	sigOff := uint32(len(blob))
	blob = append(blob, 0x03, 0x00, 0x01, 0x08)
	mrSigOff := uint32(len(blob))
	blob = append(blob, 0x03, 0x20, 0x01, 0x0E)
	tfm := ".NETFramework,Version=v4.0"
	attrVal := []byte{0x01, 0x00, byte(len(tfm))}
	attrVal = append(attrVal, tfm...)
	attrVal = append(attrVal, 0x00, 0x00)
	attrOff := uint32(len(blob))
	blob = append(blob, byte(len(attrVal)))
	blob = append(blob, attrVal...)

	// #~ stream.
	var tilde []byte
	tilde = append(tilde, make([]byte, 4)...) // Reserved
	tilde = append(tilde, 2, 0, 0, 0)         // Major, Minor, HeapSizes, Reserved
	var valid uint64
	for _, id := range []uint32{tModule, tTypeRef, tTypeDef, tMethodDef, tMemberRef, tCustomAttrib, tAssembly} {
		valid |= 1 << id
	}
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], valid)
	tilde = append(tilde, tmp[:]...)          // Valid
	tilde = append(tilde, make([]byte, 8)...) // Sorted
	rowCount := func() {
		for _, id := range []uint32{tModule, tTypeRef, tTypeDef, tMethodDef, tMemberRef, tCustomAttrib, tAssembly} {
			n := uint32(1)
			if id == tTypeDef {
				n = 2
			}
			var c [4]byte
			binary.LittleEndian.PutUint32(c[:], n)
			tilde = append(tilde, c[:]...)
		}
	}
	rowCount()
	row := func(b ...byte) { tilde = append(tilde, b...) }
	u16 := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8)} }
	u32 := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	// Module: Gen, Name, Mvid, EncId, EncBaseId.
	row(0, 0)
	tilde = append(tilde, u16(at["test.exe"])...)
	tilde = append(tilde, 0, 0, 0, 0, 0, 0)
	// TypeRef: ResolutionScope=(AssemblyRef rid0 -> tag2)=2, Name, Namespace.
	tilde = append(tilde, u16(2)...)
	tilde = append(tilde, u16(at["TargetFrameworkAttribute"])...)
	tilde = append(tilde, u16(at["System.Runtime.Versioning"])...)
	// TypeDef x2: Flags, Name, NS, Extends, FieldList, MethodList.
	tilde = append(tilde, u32(0)...)
	tilde = append(tilde, u16(at["<Module>"])...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u32(0x100000)...)
	tilde = append(tilde, u16(at["Program"])...)
	tilde = append(tilde, u16(at["NS"])...)
	tilde = append(tilde, u16(5)...) // TypeDefOrRef: TypeRef rid1
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u16(1)...)
	// MethodDef: RVA, ImplFlags, Flags, Name, Sig, ParamList.
	tilde = append(tilde, u32(0x2000)...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(0x96)...)
	tilde = append(tilde, u16(at["Main"])...)
	tilde = append(tilde, u16(sigOff)...)
	tilde = append(tilde, u16(1)...)
	// MemberRef: Class=(TypeRef rid1 -> (1<<3)|1)=9, Name, Sig.
	tilde = append(tilde, u16(9)...)
	tilde = append(tilde, u16(at[".ctor"])...)
	tilde = append(tilde, u16(mrSigOff)...)
	// CustomAttribute: Parent=(Assembly rid1 -> (1<<5)|14)=0x2E,
	// Type=(MemberRef rid1, tag 3 -> (1<<3)|3)=0x0B, Value.
	tilde = append(tilde, u16(0x2E)...)
	tilde = append(tilde, u16(0x0B)...)
	tilde = append(tilde, u16(attrOff)...)
	// Assembly: HashAlg, 1.2.3.4, Flags, PK, Name, Culture.
	tilde = append(tilde, u32(0x8004)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u16(2)...)
	tilde = append(tilde, u16(3)...)
	tilde = append(tilde, u16(4)...)
	tilde = append(tilde, u32(0)...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(at["TerrariaTest"])...)
	tilde = append(tilde, u16(0)...)

	// Metadata root.
	ver := "v4.0.30319\x00"
	for len(ver)%4 != 0 {
		ver += "\x00"
	}
	var root []byte
	root = append(root, 'B', 'S', 'J', 'B')
	root = append(root, 1, 0, 1, 0, 0, 0, 0, 0) // major, minor, reserved
	var c4 [4]byte
	binary.LittleEndian.PutUint32(c4[:], uint32(len(ver)))
	root = append(root, c4[:]...)
	root = append(root, ver...)
	root = append(root, 0, 0, 3, 0) // flags, streams
	streams := []struct {
		name string
		data []byte
	}{{"#~", tilde}, {"#Strings", strs}, {"#Blob", blob}}
	// Stream data starts after headers.
	hdrLen := 0
	for _, s := range streams {
		namePad := (len(s.name) + 1 + 3) &^ 3
		hdrLen += 8 + namePad
	}
	dataOff := len(root) + hdrLen
	for _, s := range streams {
		var h [4]byte
		binary.LittleEndian.PutUint32(h[:], uint32(dataOff))
		root = append(root, h[:]...)
		binary.LittleEndian.PutUint32(h[:], uint32(len(s.data)))
		root = append(root, h[:]...)
		root = append(root, s.name...)
		root = append(root, 0)
		for len(root)%4 != 0 {
			root = append(root, 0)
		}
		dataOff += len(s.data)
	}
	for _, s := range streams {
		root = append(root, s.data...)
	}

	// CLI header (72 bytes) + metadata in .text.
	cli := make([]byte, 72)
	put32(cli, 0, 72)
	put16(cli, 4, 2)
	put16(cli, 6, 5)
	// MetaData RVA/size filled after layout; flags ILONLY; entry MethodDef rid1.
	put32(cli, 16, 0x1)
	put32(cli, 20, 0x06000001)

	const textRVA = 0x2000
	cliRVA := uint32(textRVA)
	metaRVA := uint32(textRVA + 72)
	put32(cli, 8, metaRVA)
	put32(cli, 12, uint32(len(root)))

	// PE file: DOS + PE + COFF + OPT(224) + 1 section.
	const eLfanew = 0x80
	optSize := 224
	secOff := eLfanew + 4 + 20 + optSize
	rawData := eLfanew + 4 + 20 + optSize + 40
	rawData = (rawData + 0x1FF) &^ 0x1FF
	fileLen := rawData + 72 + len(root) + 0x200
	img := make([]byte, fileLen)
	copy(img, []byte("MZ"))
	put32(img, 0x3c, eLfanew)
	copy(img[eLfanew:], []byte("PE\x00\x00"))
	coff := eLfanew + 4
	put16(img, coff, 0x14c)
	put16(img, coff+2, 1)
	put16(img, coff+16, uint16(optSize))
	put16(img, coff+18, 0x010F)
	opt := coff + 20
	put16(img, opt, 0x10b)
	put32(img, opt+60, 0x200) // SizeOfHeaders
	put32(img, opt+92, 16)    // NumberOfRvaAndSizes
	// Data dir 14 (COM descriptor).
	put32(img, opt+96+14*8, cliRVA)
	put32(img, opt+96+14*8+4, 72)
	sec := secOff
	copy(img[sec:], []byte(".text\x00\x00\x00"))
	put32(img, sec+8, uint32(72+len(root)))
	put32(img, sec+12, textRVA)
	put32(img, sec+16, 0x200)
	put32(img, sec+20, uint32(rawData))
	copy(img[rawData:], cli)
	copy(img[rawData+72:], root)
	return img
}

func TestParseDotNetMinimal(t *testing.T) {
	img := buildMinimalDotNetPE(t)
	info, err := ParseDotNet(img)
	if err != nil {
		t.Fatalf("ParseDotNet: %v", err)
	}
	if info == nil || !info.IsDotNet {
		t.Fatalf("expected managed image, got %+v", info)
	}
	if info.RuntimeVersion != "v4.0.30319" {
		t.Errorf("runtime = %q", info.RuntimeVersion)
	}
	if info.AssemblyName != "TerrariaTest" || info.AssemblyVersion != "1.2.3.4" {
		t.Errorf("assembly = %q %q", info.AssemblyName, info.AssemblyVersion)
	}
	if info.Culture != "neutral" {
		t.Errorf("culture = %q", info.Culture)
	}
	if info.ModuleName != "test.exe" {
		t.Errorf("module = %q", info.ModuleName)
	}
	if info.EntryPointToken != 0x06000001 || info.EntryPoint != "NS.Program.Main" {
		t.Errorf("entry = %08x %q", info.EntryPointToken, info.EntryPoint)
	}
	if info.TargetFramework != ".NETFramework,Version=v4.0" {
		t.Errorf("tfm = %q", info.TargetFramework)
	}
	if info.TypeDefCount != 2 || info.MethodDefCount != 1 {
		t.Errorf("counts typedef=%d methoddef=%d", info.TypeDefCount, info.MethodDefCount)
	}
	sum := info.Summary("test.exe")
	for _, want := range []string{
		"// Entry point: NS.Program.Main",
		`[assembly: TargetFramework(".NETFramework,Version=v4.0"`,
		"// TerrariaTest, Version=1.2.3.4, Culture=neutral, PublicKeyToken=null",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
}

func TestParseDotNetNativeNegative(t *testing.T) {
	// Minimal native PE: headers only, no COM descriptor.
	img := make([]byte, 0x400)
	copy(img, []byte("MZ"))
	binary.LittleEndian.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(img[0x84:], 0x14c)
	binary.LittleEndian.PutUint16(img[0x86:], 0)   // no sections
	binary.LittleEndian.PutUint16(img[0x94:], 224) // optSize
	binary.LittleEndian.PutUint16(img[0x98:], 0x10b)
	binary.LittleEndian.PutUint32(img[0x98+60:], 0x200)
	binary.LittleEndian.PutUint32(img[0x98+92:], 16)
	info, err := ParseDotNet(img)
	if err != nil {
		t.Fatalf("ParseDotNet native: %v", err)
	}
	if info != nil {
		t.Fatalf("native image must yield (nil, nil), got %+v", info)
	}
}

func TestCustomAttributeTypeWidth(t *testing.T) {
	// Small assemblies use a 2-byte CustomAttributeType index (covers the
	// synthetic fixture above); images with >= 16384 MethodDefs (Terraria
	// has 21060) require 4 bytes — verified against production metadata
	// where 2516/2516 attribute blobs resolve only with the wide form.
	small := &tablesData{rows: map[uint32]uint32{tMethodDef: 1, tMemberRef: 1}}
	if got := small.codedSize([]uint32{tMethodDef, tMemberRef}, 2); got != 2 {
		t.Errorf("small CAT width = %d, want 2", got)
	}
	big := &tablesData{rows: map[uint32]uint32{tMethodDef: 21060, tMemberRef: 5724}}
	if got := big.codedSize([]uint32{tMethodDef, tMemberRef}, 2); got != 4 {
		t.Errorf("large CAT width = %d, want 4", got)
	}
}

func TestDebuggableModesString(t *testing.T) {
	if got := DebuggableModesString(2); got != "IgnoreSymbolStoreSequencePoints" {
		t.Errorf("got %q", got)
	}
	if got := DebuggableModesString(0); got != "None" {
		t.Errorf("got %q", got)
	}
}

func TestDeclSecurityGrantsSkipVerification(t *testing.T) {
	// Binary CAS serialization shape, as emitted for an assembly-level
	// SecurityPermission(Request*) grant: prolog, count, SerString type,
	// then PROPERTY + BOOLEAN + "SkipVerification" + value byte.
	grant := append([]byte{0x2e, 0x01, 0x04, 'T', 0x54, 0x02, 0x10},
		[]byte("SkipVerification")...)
	grant = append(grant, 0x01)
	if v, ok := declSecurityGrantsSkipVerification(grant); !ok || !v {
		t.Errorf("granting blob => (%v, %v), want (true, true)", v, ok)
	}
	deny := append([]byte{}, grant...)
	deny[len(deny)-1] = 0x00
	if v, ok := declSecurityGrantsSkipVerification(deny); !ok || v {
		t.Errorf("false grant => (%v, %v), want (false, true)", v, ok)
	}
	for _, tc := range [][]byte{nil, {}, {0x54}, {0x54, 0x02}, {0x54, 0x02, 0x10}} {
		if v, ok := declSecurityGrantsSkipVerification(tc); ok || v {
			t.Errorf("truncated %x => (%v, %v), want (false, false)", tc, v, ok)
		}
	}
}
