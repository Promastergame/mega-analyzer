package apkloader

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func parseNativeTestDEX(t *testing.T, src string) *DEXParser {
	t.Helper()
	dex, warnings, err := AssembleSmaliText("Fixture.smali", src, 0)
	if err != nil {
		t.Fatalf("native assemble: %v; warnings=%v\n%s", err, warnings, src)
	}
	p, err := ParseDEXBytes(dex)
	if err != nil {
		t.Fatalf("parse native DEX: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestNativeStandaloneParameterRegisters(t *testing.T) {
	t.Setenv("PATH", "")
	p := parseNativeTestDEX(t, `.class public Lx/Registers;
.super Ljava/lang/Object;
.method public static use(JI)I
    .locals 2
    const-string v0, "p2 must stay a string"
    invoke-static/range {p0 .. p2}, Lx/Helper;->consume(JI)V
    return p2
.end method
.method public instance(JI)I
    .registers 6
    invoke-static {p1, p2, p3}, Lx/Helper;->consume(JI)V
    return p3
.end method
`)
	c := p.FindClassByName("Lx/Registers;")
	for _, tc := range []struct {
		method    string
		registers uint16
		params    uint16
		returned  uint16
	}{
		{"use", 5, 3, 4},
		{"instance", 6, 4, 5},
	} {
		m := findMethod(c, tc.method)
		code := p.GetMethodCode(m)
		if code.RegistersSize != tc.registers || code.InsSize != tc.params {
			t.Errorf("%s: registers=%d params=%d", tc.method, code.RegistersSize, code.InsSize)
		}
		if got := code.Insns[len(code.Insns)-1]; got != tc.returned<<8|0x0f {
			t.Errorf("%s: return encodes %#x, want v%d", tc.method, got, tc.returned)
		}
	}
	code := p.GetMethodCode(findMethod(c, "use"))
	if code.Insns[2] != 0x0377 || code.Insns[4] != 2 {
		t.Fatalf("range aliases resolved incorrectly: %x", code.Insns)
	}
	if !strings.Contains(generateSmaliClass(c, p), `"p2 must stay a string"`) {
		t.Fatal("register resolution changed a string literal")
	}
}

func TestNativeStandaloneAnnotationRoundTrip(t *testing.T) {
	t.Setenv("PATH", "")
	p := parseNativeTestDEX(t, `.class public Lx/Annotated;
.super Ljava/lang/Object;
.annotation runtime Lx/Container;
    values = {
        '#',
        '}',
        '\n',
        -1t,
        2s,
        1d,
        {},
        .subannotation Lx/Nested;
            text = "a,}#"
            tags = {"one", "two"}
        .end subannotation
    }
.end annotation
.field public static count:I = 1
    .annotation runtime Lx/Field;
    .end annotation
.end field
.field public name:Ljava/lang/String;
    .annotation runtime Lx/InstanceField;
    .end annotation
.end field
.method public run(JI)V
    .locals 1
    .param p1
        .annotation runtime Lx/First;
        .end annotation
        .annotation runtime Lx/Second;
        .end annotation
    .end param
    .param p3
        .annotation runtime Lx/Third;
        .end annotation
    .end param
    .line 12
    .end local v0
    return-void
.end method
.method public static next()V
    .registers 0
    .annotation runtime Lx/Method;
    .end annotation
    return-void
.end method
`)
	c := p.FindClassByName("Lx/Annotated;")
	values := c.Annotations[0].Elements[0].Value.Elements
	for i, kind := range []byte{3, 3, 3, 0, 2, 0x11, 0x1c, 0x1d} {
		if values[i].Kind != kind {
			t.Errorf("annotation value %d: kind %#x, want %#x", i, values[i].Kind, kind)
		}
	}
	m := findMethod(c, "run")
	if len(m.ParameterAnnotations) != 2 || len(m.ParameterAnnotations[0]) != 2 || len(m.ParameterAnnotations[1]) != 1 {
		t.Fatalf("parameter annotations were lost or misindexed: %+v", m.ParameterAnnotations)
	}
	if len(findMethod(c, "next").Annotations) != 1 {
		t.Fatal("parameter annotation state leaked into the next method")
	}
	smali := generateSmaliClass(c, p)
	p2 := parseNativeTestDEX(t, smali)
	c2 := p2.FindClassByName(c.ClassName)
	if want, got := formatDEXAnnotations(c.Annotations, ""), formatDEXAnnotations(c2.Annotations, ""); want != got {
		t.Fatalf("annotations changed on native decode/build:\nwant %s\ngot %s", want, got)
	}
	m2 := findMethod(c2, "run")
	for i := range m.ParameterAnnotations {
		if formatDEXAnnotations(m.ParameterAnnotations[i], "") != formatDEXAnnotations(m2.ParameterAnnotations[i], "") {
			t.Fatalf("parameter %d changed on decode/build", i)
		}
	}
}

func TestNativeStandaloneControlFlowSurvivesLayoutChanges(t *testing.T) {
	t.Setenv("PATH", "")
	// The original const occupies three code units. Native assembly can use
	// const/4, moving the branch destination from offset 5 to offset 3.
	m := &EncodedMethod{Name: "f", AccessFlags: 0x9, ClassName: "Lx/Branch;", ReturnType: "I", Code: &CodeItem{
		RegistersSize: 1,
		Insns:         []uint16{0x0528, 0x0014, 0, 0, 0x000e, 0x7012, 0x000f},
	}}
	parser := &DEXParser{}
	c := &ClassDef{ClassName: "Lx/Branch;", SuperClass: "Ljava/lang/Object;", DirectMethods: []*EncodedMethod{m}}
	smali := generateSmaliClass(c, parser)
	if !strings.Contains(smali, "goto :label_5") {
		t.Fatalf("native output has no symbolic branch target:\n%s", smali)
	}
	p := parseNativeTestDEX(t, smali)
	code := p.GetMethodCode(findMethod(p.FindClassByName(c.ClassName), "f"))
	target := int(int8(code.Insns[0] >> 8))
	if target != 3 || code.Insns[target] != 0x7012 {
		t.Fatalf("branch moved to wrong instruction: target=%d code=%x", target, code.Insns)
	}
}

func TestNativeStandaloneSwitchRoundTrip(t *testing.T) {
	t.Setenv("PATH", "")
	for _, tc := range []struct{ name, op, payload string }{
		{"packed", "packed-switch", ".packed-switch -0x1\n        :seven\n    .end packed-switch"},
		{"sparse", "sparse-switch", ".sparse-switch\n        -0x1 -> :seven\n    .end sparse-switch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `.class public Lx/Switch;
.super Ljava/lang/Object;
.method public static pick(I)I
    .locals 1
    ` + tc.op + ` p0, :data
    const/4 v0, 1
    return v0
    :seven
    const/4 v0, 7
    return v0
    :data
    :alias
    ` + tc.payload + `
.end method
`
			p := parseNativeTestDEX(t, src)
			c := p.FindClassByName("Lx/Switch;")
			smali := generateSmaliClass(c, p)
			// Expanding the default path moves the switch target and payload.
			smali = strings.Replace(smali, "const/4 v0, 1", "const v0, 70000", 1)
			p2 := parseNativeTestDEX(t, smali)
			code := p2.GetMethodCode(findMethod(p2.FindClassByName(c.ClassName), "pick"))
			payload := int(uint32(code.Insns[1]) | uint32(code.Insns[2])<<16)
			if payload%2 != 0 || payload+5 >= len(code.Insns) {
				t.Fatalf("invalid payload target %d: %x", payload, code.Insns)
			}
			target := int(int32(uint32(code.Insns[payload+4]) | uint32(code.Insns[payload+5])<<16))
			if target != 7 || code.Insns[target] != 0x7012 {
				t.Fatalf("switch target changed after edit: target=%d code=%x\n%s", target, code.Insns, smali)
			}
		})
	}
}

func TestNativeStandaloneTrailingTryLabel(t *testing.T) {
	t.Setenv("PATH", "")
	p := parseNativeTestDEX(t, `.class public Lx/Try;
.super Ljava/lang/Object;
.method public static run()V
    .registers 1
    :handler
    move-exception v0
    return-void
    :start
    new-instance v0, Ljava/lang/RuntimeException;
    throw v0
    :end
    .catchall {:start .. :end} :handler
.end method
`)
	c := p.FindClassByName("Lx/Try;")
	p2 := parseNativeTestDEX(t, generateSmaliClass(c, p))
	code := p2.GetMethodCode(findMethod(p2.FindClassByName(c.ClassName), "run"))
	if len(code.Tries) != 1 || code.Tries[0].StartAddr+uint32(code.Tries[0].InsnCount) != uint32(len(code.Insns)) {
		t.Fatalf("trailing try label lost: %+v", code.Tries)
	}
}

func TestNativeStandaloneSharedSwitchPayload(t *testing.T) {
	p := parseNativeTestDEX(t, `.class public Lx/Shared;
.super Ljava/lang/Object;
.method public static run(I)I
    .locals 1
    packed-switch p0, :data
    const/4 v0, 1
    return v0
    const/4 v0, 7
    return v0
    packed-switch p0, :data
    const/4 v0, 2
    return v0
    const/16 v0, 9
    return v0
    :data
    .packed-switch 0
        +5
    .end packed-switch
.end method
`)
	c := p.FindClassByName("Lx/Shared;")
	smali := generateSmaliClass(c, p)
	if strings.Count(smali, ".packed-switch 0x0") != 2 {
		t.Fatalf("shared payload was not split into independent symbolic blocks:\n%s", smali)
	}
	smali = strings.Replace(smali, "const/4 v0, 1", "const v0, 70000", 1)
	p2 := parseNativeTestDEX(t, smali)
	code := p2.GetMethodCode(findMethod(p2.FindClassByName(c.ClassName), "run"))
	for i, pos := range []uint32{0, 9} {
		rel, ok := smaliBranchOffset(code.Insns, pos)
		if !ok {
			t.Fatalf("switch missing at %d", pos)
		}
		payload := uint32(int64(pos) + rel)
		offset := int32(uint32(code.Insns[payload+4]) | uint32(code.Insns[payload+5])<<16)
		target := uint32(int64(pos) + int64(offset))
		want := []uint16{0x7012, 0x0013}[i]
		if code.Insns[target] != want {
			t.Fatalf("switch %d resolved to %d (%#x), want opcode %#x", i, target, code.Insns[target], want)
		}
	}
}

func TestNativeStandaloneRejectsIncompleteInputs(t *testing.T) {
	for _, body := range []string{
		".annotation runtime Lx/A;\nvalue = 1\n",
		".method public static f()V\nreturn-void\n.end method\n",
		".method public static f()V\n.registers 1\nreturn p0\n.end method\n",
		".method public f(J)V\n.registers 2\nreturn-void\n.end method\n",
		".method public static f()I\n.registers 1\nreturn v1\n.end method\n",
		".method public abstract f()V\n.registers 1\nreturn-void\n.end method\n",
		".method public static f()I\n.registers 257\nreturn v256\n.end method\n",
		".method public static f()I\n.registers 1\nconst/4 v0, 100\nreturn v0\n.end method\n",
	} {
		src := ".class public Lx/Bad;\n.super Ljava/lang/Object;\n" + body
		if _, _, err := AssembleSmaliText("Bad.smali", src, 0); err == nil {
			t.Errorf("expected error for incomplete/invalid source:\n%s", src)
		}
	}
	_, _, err := AssembleSmaliDirNative(filepath.Join(testutil.TempDir(t), "missing"), 0)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing tree must report filesystem failure, got %v", err)
	}
}

func TestNativeStandaloneDEXMapStructure(t *testing.T) {
	dex, _, err := AssembleSmaliText("Hello.smali", nativeHelloSmali, 0)
	if err != nil {
		t.Fatal(err)
	}
	u32 := func(at int) uint32 { return binary.LittleEndian.Uint32(dex[at : at+4]) }
	mapAt := int(u32(52))
	count := int(u32(mapAt))
	entries := map[uint16][2]uint32{}
	var previous uint32
	for i := 0; i < count; i++ {
		at := mapAt + 4 + i*12
		typ := binary.LittleEndian.Uint16(dex[at : at+2])
		size, offset := u32(at+4), u32(at+8)
		if size == 0 || (i > 0 && offset <= previous) {
			t.Fatalf("invalid map item type=%#x size=%d offset=%d previous=%d", typ, size, offset, previous)
		}
		previous = offset
		entries[typ] = [2]uint32{size, offset}
	}
	for _, tc := range []struct {
		typ    uint16
		header int
	}{
		{mapStringID, 56}, {mapTypeID, 64}, {mapProtoID, 72}, {mapFieldID, 80}, {mapMethodID, 88}, {mapClassDef, 96},
	} {
		if got, want := entries[tc.typ], [2]uint32{u32(tc.header), u32(tc.header + 4)}; got != want {
			t.Errorf("map type %#x=%v, header=%v", tc.typ, got, want)
		}
	}
	if entries[mapStringData][0] != u32(56) {
		t.Fatal("string data item count differs from string ids")
	}
	// string_data_item is byte-aligned: no padding between sequential items.
	stringIDs := int(u32(60))
	for i := uint32(0); i+1 < u32(56); i++ {
		at := int(u32(stringIDs + int(i)*4))
		for dex[at]&0x80 != 0 {
			at++
		}
		at++ // UTF-16 length ULEB
		for dex[at] != 0 {
			at++
		}
		if next := int(u32(stringIDs + int(i+1)*4)); next != at+1 {
			t.Fatalf("padding between string items %d: end=%d next=%d", i, at+1, next)
		}
	}
}

func TestNativeStandaloneDemoProject(t *testing.T) {
	t.Setenv("PATH", "")
	input := filepath.Join("..", "..", "..", "demo", "demo_test_apk", "decompiled", "classes.dex")
	if _, err := os.Stat(input); err != nil {
		t.Skip("repository demo fixture not present")
	}
	original, err := ParseDEX(input)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	dir := testutil.TempDir(t)
	if err := NewExtractor().generateSmaliOutput(t.Context(), original, dir, 2, smaliOutputOptions{}); err != nil {
		t.Fatalf("standalone demo decode: %v", err)
	}
	dex, warnings, err := AssembleSmaliDirNative(dir, 0)
	if err != nil {
		t.Fatalf("standalone demo build: %v; warnings=%v", err, warnings)
	}
	p, err := ParseDEXBytes(dex)
	if err != nil {
		t.Fatalf("read standalone demo build: %v", err)
	}
	defer p.Close()
	if len(p.GetClasses()) != len(original.GetClasses()) {
		t.Fatalf("demo classes missing: got %d want %d", len(p.GetClasses()), len(original.GetClasses()))
	}
}
