package peinspect

// Tests for the IL call walker: a full synthetic image (Main calls
// MemberRef Assembly::Load) plus unit coverage for the decoder edges
// (calli/ldftn, switch, truncation, unknown opcodes, token fallback,
// MethodSpec, fat headers, the 2048-site cap).

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildILCallFixturePE synthesizes a CLI image whose Main method body is:
//
//	call MemberRef(Assembly::Load); ret
//
// A second MethodDef has RVA 0 (no body) and must be skipped.
func buildILCallFixturePE(t *testing.T) []byte {
	t.Helper()
	put16 := func(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	put32 := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

	strs := []byte{0}
	at := map[string]uint32{}
	addStr := func(s string) {
		at[s] = uint32(len(strs))
		strs = append(strs, s...)
		strs = append(strs, 0)
	}
	for _, s := range []string{"test.exe", "<Module>", "Program", "NS", "Main", "Helper", "Assembly", "System.Reflection", "Load"} {
		addStr(s)
	}

	blob := []byte{0x00}
	sigOff := uint32(len(blob))
	blob = append(blob, 0x00, 0x00, 0x01, 0x08) // Main(): static void()
	mrSigOff := uint32(len(blob))
	blob = append(blob, 0x00, 0x01, 0x0E) // Load(string): static string()

	var tilde []byte
	tilde = append(tilde, make([]byte, 4)...)
	tilde = append(tilde, 2, 0, 0, 0)
	var valid uint64
	tables := []uint32{tModule, tTypeRef, tTypeDef, tMethodDef, tMemberRef}
	for _, id := range tables {
		valid |= 1 << id
	}
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], valid)
	tilde = append(tilde, tmp[:]...)
	tilde = append(tilde, make([]byte, 8)...)
	counts := map[uint32]uint32{tModule: 1, tTypeRef: 1, tTypeDef: 2, tMethodDef: 2, tMemberRef: 1}
	for _, id := range tables {
		var c [4]byte
		binary.LittleEndian.PutUint32(c[:], counts[id])
		tilde = append(tilde, c[:]...)
	}
	row := func(b ...byte) { tilde = append(tilde, b...) }
	u16 := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8)} }
	u32 := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	// Module.
	row(0, 0)
	tilde = append(tilde, u16(at["test.exe"])...)
	tilde = append(tilde, 0, 0, 0, 0, 0, 0)
	// TypeRef rid1: scope=null, Name=Assembly, NS=System.Reflection.
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(at["Assembly"])...)
	tilde = append(tilde, u16(at["System.Reflection"])...)
	// TypeDef <Module> + Program (MethodList 1).
	tilde = append(tilde, u32(0)...)
	tilde = append(tilde, u16(at["<Module>"])...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u32(0x100000)...)
	tilde = append(tilde, u16(at["Program"])...)
	tilde = append(tilde, u16(at["NS"])...)
	tilde = append(tilde, u16(5)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u16(1)...)
	// MethodDef rid1 Main (RVA patched below), rid2 Helper (RVA 0).
	bodyRVAPl := len(tilde) // placeholder offset for the RVA field
	tilde = append(tilde, u32(0)...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(0x96)...)
	tilde = append(tilde, u16(at["Main"])...)
	tilde = append(tilde, u16(sigOff)...)
	tilde = append(tilde, u16(1)...)
	tilde = append(tilde, u32(0)...)
	tilde = append(tilde, u16(0)...)
	tilde = append(tilde, u16(0x96)...)
	tilde = append(tilde, u16(at["Helper"])...)
	tilde = append(tilde, u16(sigOff)...)
	tilde = append(tilde, u16(1)...)
	// MemberRef rid1: Class=(TypeRef rid1)=9, Name=Load.
	tilde = append(tilde, u16(9)...)
	tilde = append(tilde, u16(at["Load"])...)
	tilde = append(tilde, u16(mrSigOff)...)

	// Metadata root.
	ver := "v4.0.30319\x00"
	for len(ver)%4 != 0 {
		ver += "\x00"
	}
	var root []byte
	root = append(root, 'B', 'S', 'J', 'B')
	root = append(root, 1, 0, 1, 0, 0, 0, 0, 0)
	var c4 [4]byte
	binary.LittleEndian.PutUint32(c4[:], uint32(len(ver)))
	root = append(root, c4[:]...)
	root = append(root, ver...)
	root = append(root, 0, 0, 3, 0)
	streams := []struct {
		name string
		data []byte
	}{{"#~", tilde}, {"#Strings", strs}, {"#Blob", blob}}
	hdrLen := 0
	for _, s := range streams {
		hdrLen += 8 + ((len(s.name) + 1 + 3) &^ 3)
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

	// Method body after the metadata: tiny header, call 0x0A000001, ret.
	const textRVA = 0x2000
	bodyRVA := uint32(textRVA + 72 + len(root))
	body := []byte{0x1A, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A}
	binary.LittleEndian.PutUint32(tilde[bodyRVAPl:], bodyRVA)

	cli := make([]byte, 72)
	put32(cli, 0, 72)
	put16(cli, 4, 2)
	put16(cli, 6, 5)
	put32(cli, 8, uint32(textRVA+72))
	put32(cli, 12, uint32(len(root)))
	put32(cli, 16, 0x1)
	put32(cli, 20, 0x06000001)

	const eLfanew = 0x80
	optSize := 224
	secOff := eLfanew + 4 + 20 + optSize
	rawData := (eLfanew + 4 + 20 + optSize + 40 + 0x1FF) &^ 0x1FF
	img := make([]byte, rawData+72+len(root)+len(body)+0x200)
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
	put32(img, opt+60, 0x200)
	put32(img, opt+92, 16)
	put32(img, opt+96+14*8, uint32(textRVA))
	put32(img, opt+96+14*8+4, 72) // COM descriptor size is the CLI header size
	sec := secOff
	copy(img[sec:], []byte(".text\x00\x00\x00"))
	put32(img, sec+8, uint32(72+len(root)+len(body)))
	put32(img, sec+12, textRVA)
	put32(img, sec+16, 0x200)
	put32(img, sec+20, uint32(rawData))
	copy(img[rawData:], cli)
	copy(img[rawData+72:], root)
	// Re-emit the #~ stream with the patched MethodDef RVA.
	rootOff := rawData + 72
	tildeOff := rootOff + (len(root) - len(tilde) - len(strs) - len(blob))
	copy(img[tildeOff:], tilde)
	copy(img[rawData+72+len(root):], body)
	return img
}

func TestILCallsMinimalFixture(t *testing.T) {
	img := buildILCallFixturePE(t)
	info, err := ParseDotNet(img)
	if err != nil {
		t.Fatalf("ParseDotNet: %v", err)
	}
	if info == nil || !info.IsDotNet {
		t.Fatalf("expected managed image")
	}
	if info.ILMethodsWalked != 1 {
		t.Errorf("ILMethodsWalked = %d, want 1 (Helper has no body)", info.ILMethodsWalked)
	}
	if len(info.ILCallSites) != 1 {
		t.Fatalf("ILCallSites = %+v, want exactly one call", info.ILCallSites)
	}
	s := info.ILCallSites[0]
	if s.Caller != "NS.Program.Main" || s.Op != "call" || s.ILOffset != 0 {
		t.Errorf("site = %+v, want NS.Program.Main call @0", s)
	}
	if s.Token != 0x0A000001 {
		t.Errorf("token = 0x%08X, want 0x0A000001", s.Token)
	}
	// memberRefParentName resolves the declaring type without namespace.
	if s.Target != "Assembly::Load" {
		t.Errorf("target = %q, want Assembly::Load", s.Target)
	}
	if s.Indirect {
		t.Errorf("static call must not be indirect")
	}
	if info.EntryPoint != "NS.Program.Main" {
		t.Errorf("entry = %q", info.EntryPoint)
	}
}

// ilUnitTables builds a tablesData with one TypeDef (NS.Program), one
// MethodDef (Main), one TypeRef (Assembly), one MemberRef (Load) and one
// MethodSpec over that MemberRef.
func ilUnitTables(t *testing.T) *tablesData {
	t.Helper()
	strs := []byte{0}
	at := map[string]uint16{}
	add := func(s string) {
		at[s] = uint16(len(strs))
		strs = append(strs, s...)
		strs = append(strs, 0)
	}
	for _, s := range []string{"Program", "NS", "Main", "Assembly", "Load"} {
		add(s)
	}
	u16 := func(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
	u32 := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	// TypeDef: flags, name, ns, extends=0, field=1, method=1.
	typeDef := append(u32(0), u16(at["Program"])...)
	typeDef = append(typeDef, u16(at["NS"])...)
	typeDef = append(typeDef, concat(u16(0), u16(1), u16(1))...)
	// MethodDef: rva, impl, flags, name, sig=0, param=1.
	methodDef := append(u32(0x2000), concat(u16(0), u16(0x96))...)
	methodDef = append(methodDef, concat(u16(at["Main"]), u16(0), u16(1))...)
	// TypeRef: scope=0, name=Assembly, ns=0.
	typeRef := append(u16(0), u16(at["Assembly"])...)
	typeRef = append(typeRef, u16(0)...)
	// MemberRef: class=(TypeRef rid1)=9, name=Load, sig=0.
	memberRef := append(u16(9), u16(at["Load"])...)
	memberRef = append(memberRef, u16(0)...)
	// MethodSpec: MethodDefOrRef=(MemberRef rid1, tag1)=3, blob=0.
	methodSpec := append(u16(3), u16(0)...)
	return &tablesData{
		strings: strs,
		rows:    map[uint32]uint32{tTypeDef: 1, tMethodDef: 1, tTypeRef: 1, tMemberRef: 1, 0x2B: 1},
		raw: map[uint32][]byte{
			tTypeDef:   typeDef,
			tMethodDef: methodDef,
			tTypeRef:   typeRef,
			tMemberRef: memberRef,
			0x2B:       methodSpec,
		},
		strSz: 2, guidSz: 2, blobSz: 2,
	}
}

func walkOne(t *testing.T, td *tablesData, code []byte) *DotNetInfo {
	t.Helper()
	info := &DotNetInfo{}
	walkILBody(td, info, "NS.Program.Main", code)
	return info
}

func tokCall(token uint32) []byte {
	return []byte{0x28, byte(token), byte(token >> 8), byte(token >> 16), byte(token >> 24)}
}

func TestILWalkerOps(t *testing.T) {
	td := ilUnitTables(t)

	// callvirt + newobj + jmp resolve like call.
	code := append(tokCall(0x06000001), 0x6F, 1, 0, 6, 0, 0x73, 1, 0, 10, 0, 0x27, 1, 0, 43, 0)
	info := walkOne(t, td, code)
	if len(info.ILCallSites) != 4 {
		t.Fatalf("sites = %+v, want 4", info.ILCallSites)
	}
	for i, want := range []string{"call", "callvirt", "newobj", "jmp"} {
		if info.ILCallSites[i].Op != want {
			t.Errorf("site %d op = %q, want %q", i, info.ILCallSites[i].Op, want)
		}
	}
	if info.ILCallSites[0].Target != "NS.Program.Main" {
		t.Errorf("methoddef target = %q", info.ILCallSites[0].Target)
	}

	// calli + ldftn/ldvirtftn are indirect.
	code = []byte{0x29, 1, 0, 10, 0, 0xFE, 0x06, 1, 0, 10, 0, 0xFE, 0x07, 1, 0, 6, 0}
	info = walkOne(t, td, code)
	if len(info.ILCallSites) != 3 {
		t.Fatalf("sites = %+v, want 3", info.ILCallSites)
	}
	for i, want := range []string{"calli", "ldftn", "ldvirtftn"} {
		if info.ILCallSites[i].Op != want || !info.ILCallSites[i].Indirect {
			t.Errorf("site %d = %+v, want %q indirect", i, info.ILCallSites[i], want)
		}
	}

	// Unknown opcode aborts the method but keeps prior sites.
	code = append(tokCall(0x0A000001), 0xFF, 0x28, 1, 0, 10, 0)
	info = walkOne(t, td, code)
	if len(info.ILCallSites) != 1 || info.ILCallSites[0].Target != "Assembly::Load" {
		t.Fatalf("sites = %+v, want single Load before 0xFF", info.ILCallSites)
	}

	// Truncated operand yields no site, no panic.
	for _, tc := range [][]byte{{0x28, 0x01}, {0x28}, {0xFE}, {0x45, 0x01}} {
		if info := walkOne(t, td, tc); len(info.ILCallSites) != 0 {
			t.Errorf("truncated %x => %+v, want none", tc, info.ILCallSites)
		}
	}

	// switch (0x45) skips its jump table; the call after it is found.
	code = []byte{0x45, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0}
	code = append(code, tokCall(0x0A000001)...)
	info = walkOne(t, td, code)
	if len(info.ILCallSites) != 1 {
		t.Fatalf("sites after switch = %+v, want 1", info.ILCallSites)
	}

	// Missing row falls back to the raw token; MethodSpec unwraps one level.
	code = append(tokCall(0x0A00FFFF), tokCall(0x2B000001)...)
	info = walkOne(t, td, code)
	if len(info.ILCallSites) != 2 {
		t.Fatalf("sites = %+v, want 2", info.ILCallSites)
	}
	if info.ILCallSites[0].Target != "token 0x0A00FFFF" {
		t.Errorf("missing row target = %q", info.ILCallSites[0].Target)
	}
	if info.ILCallSites[1].Target != "Assembly::Load[generic]" {
		t.Errorf("methodspec target = %q", info.ILCallSites[1].Target)
	}
}

func TestILReadMethodBody(t *testing.T) {
	// Tiny body: 2-byte code (ret, ret).
	tiny := []byte{0x0A, 0x2A, 0x2A}
	code, ok := readMethodBody(append([]byte{0xFF}, tiny...), 1)
	if !ok || len(code) != 2 {
		t.Fatalf("tiny body = %x, %v", code, ok)
	}
	// Fat body with the same code.
	fat := []byte{0x13, 0x30, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x2A}
	code, ok = readMethodBody(fat, 0)
	if !ok || len(code) != 2 {
		t.Fatalf("fat body = %x, %v", code, ok)
	}
	// Fat body with more-sections flag still reads codeSize bytes.
	fat[1] |= 0x10
	if _, ok = readMethodBody(fat, 0); !ok {
		t.Error("fat body with extra sections must still parse")
	}
	for _, tc := range [][]byte{
		{}, {0x00}, {0x01}, // empty / invalid header tag bits
		{0x0A},       // tiny size overruns
		{0x13, 0x30}, // fat header truncated
		{0x13, 0x30, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0, 0, 0, 0}, // code overruns
	} {
		if _, ok := readMethodBody(tc, 0); ok {
			t.Errorf("malformed %x must not parse", tc)
		}
	}
	if _, ok := readMethodBody([]byte{0x0A, 0x2A}, 99); ok {
		t.Error("out-of-range offset must not parse")
	}
}

func TestILCallCap(t *testing.T) {
	td := ilUnitTables(t)
	info := &DotNetInfo{}
	for i := 0; i < maxILCallSites; i++ {
		info.ILCallSites = append(info.ILCallSites, ILCallSite{Op: "call"})
	}
	walkILBody(td, info, "M", tokCall(0x0A000001))
	if !info.ILTruncated {
		t.Error("cap hit must set ILTruncated")
	}
	if len(info.ILCallSites) != maxILCallSites {
		t.Errorf("sites = %d, want cap %d", len(info.ILCallSites), maxILCallSites)
	}
}

func TestILNoDotNetNoCalls(t *testing.T) {
	// The pre-existing minimal fixture points Main at the CLI header, which
	// is not a method body: zero sites, zero walked, no error.
	img := buildMinimalDotNetPE(t)
	info, err := ParseDotNet(img)
	if err != nil {
		t.Fatalf("ParseDotNet: %v", err)
	}
	if len(info.ILCallSites) != 0 || info.ILMethodsWalked != 0 || info.ILTruncated {
		t.Errorf("CLI-header RVA must yield no callsites: %+v", info.ILCallSites)
	}
	if !strings.Contains(info.Summary("x"), "NS.Program.Main") {
		t.Error("summary must be unaffected by the walker")
	}
}
