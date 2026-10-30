package apkloader

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"strings"
	"testing"
)

func androidPatcherDEXFixture(t *testing.T, method string) *DEXParser {
	t.Helper()
	src := ".class public Laudit/Probe;\n.super Ljava/lang/Object;\n" + method
	data, _, err := AssembleSmaliText("Probe.smali", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseDEXBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAndroidPatcherDEXChecksumsAfterPatch(t *testing.T) {
	p := androidPatcherDEXFixture(t, ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\nreturn v0\n.end method\n")
	beforeSHA := sha1.Sum(p.data[32:])
	if !bytes.Equal(p.data[12:32], beforeSHA[:]) || binary.LittleEndian.Uint32(p.data[8:12]) != adler32.Checksum(p.data[12:]) {
		t.Fatal("invalid input fixture")
	}
	out, err := NewMLPatchBridge(p).ExecuteAndSplice(NewPatchPlanBuilder("Laudit/Probe;->value()Z").ReturnTrue().Build())
	if err != nil {
		t.Fatal(err)
	}
	_, parseErr := ParseDEXBytes(out)
	t.Logf("ParseDEXBytes accepts patched output: %v", parseErr == nil)
	wantSHA := sha1.Sum(out[32:])
	if !bytes.Equal(out[12:32], wantSHA[:]) {
		t.Errorf("DEX SHA-1 is stale after a successful patch")
	}
	if got, want := binary.LittleEndian.Uint32(out[8:12]), adler32.Checksum(out[12:]); got != want {
		t.Errorf("DEX Adler-32 is stale: got %08x, want %08x", got, want)
	}
}

func TestAndroidPatcherDEXRegisterEncoding(t *testing.T) {
	p := androidPatcherDEXFixture(t, ".method public static value()Z\n.locals 17\nconst/4 v0, 0x0\nreturn v0\n.end method\n")
	bridge := NewMLPatchBridge(p)
	out, err := bridge.ExecuteAndSplice(NewPatchPlanBuilder("Laudit/Probe;->value()Z").ReturnTrue().Build())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDEXBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMLPatchBridge(parsed).findEncodedMethod("Laudit/Probe;->value()Z")
	words := m.Code.Insns
	written := (words[0] >> 8) & 0xf
	returned := words[1] >> 8
	if written != returned {
		t.Fatalf("successful true stub writes v%d but returns v%d (registers=%d, words=%04x)", written, returned, m.Code.RegistersSize, words)
	}
}

func TestAndroidPatcherDEXWideRegisterPair(t *testing.T) {
	p := androidPatcherDEXFixture(t, ".method public static value()J\n.locals 2\nconst-wide/16 v0, 0x0\nreturn-wide v0\n.end method\n")
	bridge := NewMLPatchBridge(p)
	_, err := bridge.ExecuteAndSplice(NewPatchPlanBuilder("Laudit/Probe;->value()J").ReturnFalse().Build())
	if err != nil {
		t.Fatal(err)
	}
	m := bridge.findEncodedMethod("Laudit/Probe;->value()J")
	first := m.Code.Insns[0] >> 8
	if first+1 >= m.Code.RegistersSize {
		t.Fatalf("successful wide stub uses v%d:v%d with registers_size=%d", first, first+1, m.Code.RegistersSize)
	}
}

func TestAndroidPatcherDEXReferenceIndices(t *testing.T) {
	method := ".method public static value()Z\n.locals 1\ninvoke-static {}, Laudit/Probe;->record()V\nconst/4 v0, 0x0\nreturn v0\n.end method"
	p := androidPatcherDEXFixture(t, ".method public static aaa()V\n.locals 0\nreturn-void\n.end method\n"+method)
	before := bytes.Clone(p.data)
	out, changed, err := PatchDEXMethod(p.data, "Laudit/Probe;->value()Z", method, strings.Replace(method, "0x0", "0x1", 1))
	if err != nil || !changed {
		t.Fatalf("patch: changed=%v err=%v", changed, err)
	}
	if !bytes.Equal(before, p.data) {
		t.Fatal("patch modified caller's input buffer")
	}
	result, err := ParseDEXBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMLPatchBridge(result).findEncodedMethod("Laudit/Probe;->value()Z")
	ref := result.methods[m.Code.Insns[1]]
	if byte(m.Code.Insns[0]) != 0x71 || ref.MethodName != "record" || ref.ClassName != "Laudit/Probe;" {
		t.Fatalf("invoke reference was remapped: %+v", ref)
	}
	if err := verifyDEXIntegrity(out); err != nil {
		t.Fatal(err)
	}
}

func TestAndroidPatcherDEXParametersAndWideReturn(t *testing.T) {
	for _, tc := range []struct{ descriptor, original, patched string }{
		{"value(I)I", ".method public static value(I)I\n.locals 1\nmove v0, p0\nreturn v0\n.end method", ".method public static value(I)I\n.locals 1\nconst/4 v0, 0x1\nreturn v0\n.end method"},
		{"value()J", ".method public static value()J\n.locals 2\nconst-wide/16 v0, 0x1\nreturn-wide v0\n.end method", ".method public static value()J\n.locals 2\nconst-wide/16 v0, 0x0\nreturn-wide v0\n.end method"},
	} {
		t.Run(tc.descriptor, func(t *testing.T) {
			p := androidPatcherDEXFixture(t, tc.original)
			out, changed, err := PatchDEXMethod(p.data, "Laudit/Probe;->"+tc.descriptor, tc.original, tc.patched)
			if err != nil || !changed {
				t.Fatalf("patch: changed=%v err=%v", changed, err)
			}
			if _, changed, err := PatchDEXMethod(out, "Laudit/Probe;->"+tc.descriptor, tc.original, tc.patched); err != nil || changed {
				t.Fatalf("idempotence: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestAndroidPatcherDEXRejectsUnrepresentableEdits(t *testing.T) {
	for _, tc := range []struct{ name, descriptor, original, patched string }{
		{"growth", "value(Z)Z", ".method public static value(Z)Z\n.locals 0\nreturn p0\n.end method", ".method public static value(Z)Z\n.locals 1\nconst/4 v0, 0x1\nreturn v0\n.end method"},
		{"new reference", "value()Ljava/lang/String;", ".method public static value()Ljava/lang/String;\n.locals 1\nconst-string v0, \"old\"\nreturn-object v0\n.end method", ".method public static value()Ljava/lang/String;\n.locals 1\nconst-string v0, \"new\"\nreturn-object v0\n.end method"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := androidPatcherDEXFixture(t, tc.original)
			before := bytes.Clone(p.data)
			if _, _, err := PatchDEXMethod(p.data, "Laudit/Probe;->"+tc.descriptor, tc.original, tc.patched); err == nil || !strings.Contains(err.Error(), "rebuild") {
				t.Fatalf("expected explicit rebuild requirement, got %v", err)
			}
			if !bytes.Equal(before, p.data) {
				t.Fatal("failed patch modified input")
			}
		})
	}
}

func TestAndroidPatcherDEXPreservesCatchLayout(t *testing.T) {
	method := ".method public static value()I\n.locals 1\n:try_start\ninvoke-static {}, Laudit/Probe;->record()V\n:try_end\n.catch Ljava/lang/Exception; {:try_start .. :try_end} :handler\nconst/4 v0, 0x0\nreturn v0\n:handler\nmove-exception v0\nconst/4 v0, -0x1\nreturn v0\n.end method"
	p := androidPatcherDEXFixture(t, method)
	out, changed, err := PatchDEXMethod(p.data, "Laudit/Probe;->value()I", method, strings.Replace(method, "const/4 v0, 0x0", "const/4 v0, 0x1", 1))
	if err != nil || !changed {
		t.Fatalf("catch-preserving patch: changed=%v err=%v", changed, err)
	}
	q, err := ParseDEXBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMLPatchBridge(q).findEncodedMethod("Laudit/Probe;->value()I")
	if m.Code.TriesSize != 1 || m.Code.Tries[0].CatchHandlers[0].TypeName != "Ljava/lang/Exception;" {
		t.Fatal("exception handler lost")
	}
	if _, err := NewMLPatchBridge(p).ExecuteAndSplice(NewPatchPlanBuilder("Laudit/Probe;->value()I").ReturnTrue().Build()); err == nil {
		t.Fatal("whole-method stub accepted a catch region")
	}
}

func TestAndroidPatcherStubOperandWidth(t *testing.T) {
	units, err := stubUnitsFor("Z", PatchReturnTrue, 16)
	if err != nil || len(units) != 3 || units[0] != 0x1013 || units[1] != 1 || units[2] != 0x100f {
		t.Fatalf("wide const form: %04x %v", units, err)
	}
	if _, err := stubUnitsFor("Z", PatchReturnTrue, 256); err == nil {
		t.Fatal("unencodable return register accepted")
	}
}

func TestAndroidPatcherDEXRejectsUnsafeCodeItems(t *testing.T) {
	method := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\nreturn v0\n.end method"
	first := strings.Replace(method, "value()", "first()", 1)
	for _, kind := range []string{"shared", "duplicate", "parameters", "exceptions"} {
		t.Run(kind, func(t *testing.T) {
			p := androidPatcherDEXFixture(t, first+"\n"+method)
			cls := p.FindClassByName("Laudit/Probe;")
			data := bytes.Clone(p.data)
			offset := cls.ClassDataOff
			read := func() uint32 {
				value, n := p.readULEB128At(offset)
				if n == 0 {
					t.Fatal("invalid fixture class data")
				}
				offset += uint32(n)
				return value
			}
			counts := [4]uint32{read(), read(), read(), read()}
			if counts != [4]uint32{0, 0, 2, 0} {
				t.Fatalf("unexpected fixture members: %v", counts)
			}
			var indices, codeOffsets [2]uint32
			for i := range indices {
				indices[i] = offset
				read()
				read() // access flags
				codeOffsets[i] = offset
				read()
			}
			writeULEB := func(at, value uint32) {
				_, oldSize := p.readULEB128At(at)
				var encoded [5]byte
				n := binary.PutUvarint(encoded[:], uint64(value))
				if n != oldSize {
					t.Fatal("fixture mutation must preserve encoded width")
				}
				copy(data[at:at+uint32(n)], encoded[:n])
			}
			original, descriptor, wantError := method, "Laudit/Probe;->value()Z", ""
			switch kind {
			case "shared":
				writeULEB(codeOffsets[1], cls.DirectMethods[0].CodeOff)
				wantError = "shared"
			case "duplicate":
				writeULEB(indices[1], 0)
				original, descriptor, wantError = first, "Laudit/Probe;->first()Z", "ambiguous"
			case "parameters":
				putU16(data, cls.DirectMethods[1].CodeOff+2, 1)
				wantError = "register frame"
			case "exceptions":
				putU16(data, cls.DirectMethods[1].CodeOff+6, 0xffff)
				wantError = "exception table"
			}
			if err := finalizeDEX(data); err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(data)
			if _, _, err := PatchDEXMethod(data, descriptor, original, strings.Replace(original, "0x0", "0x1", 1)); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("expected %s rejection, got %v", kind, err)
			}
			if !bytes.Equal(before, data) {
				t.Fatal("rejected patch changed input")
			}
		})
	}
}

func TestAndroidPatcherDEXAnnotationsAndIdempotence(t *testing.T) {
	method := ".method public static value(I)Z\n.locals 1\n.annotation runtime Laudit/Marker;\n.end annotation\n.param p0\n.annotation runtime Laudit/Argument;\n.end annotation\n.end param\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(method, "const/4 v0, 0x0", "const/4 v0, 0x1", 1)
	const descriptor = "Laudit/Probe;->value(I)Z"
	p := androidPatcherDEXFixture(t, method)
	out, changed, err := PatchDEXMethod(p.data, descriptor, method, patched)
	if err != nil || !changed {
		t.Fatalf("annotated method patch: changed=%v err=%v", changed, err)
	}
	if _, changed, err := PatchDEXMethod(out, descriptor, method, patched); err != nil || changed {
		t.Fatalf("annotated method repeat: changed=%v err=%v", changed, err)
	}
	for _, annotation := range []string{"Laudit/Marker;", "Laudit/Argument;"} {
		t.Run(annotation, func(t *testing.T) {
			drifted := androidPatcherDEXFixture(t, strings.Replace(patched, ".annotation runtime "+annotation, ".annotation build "+annotation, 1))
			if _, _, err := PatchDEXMethod(drifted.data, descriptor, method, patched); err == nil || !strings.Contains(err.Error(), "annotations drifted") {
				t.Fatalf("already-applied check ignored annotation drift: %v", err)
			}
		})
	}
}
