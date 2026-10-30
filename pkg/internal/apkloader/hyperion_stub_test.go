package apkloader

import (
	"testing"
)

// Dalvik code units are little-endian: OPCODE is always the LOW byte.
// 11n const/4: op(8) | A<<8 | B<<12. AA-form: op | AA<<8.

func TestStubUnitsForBooleanTrue(t *testing.T) {
	units, err := stubUnitsFor("Z", PatchReturnTrue, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{0x1012, 0x000F} // const/4 v0,1 ; return v0
	if units[0] != want[0] || units[1] != want[1] {
		t.Fatalf("units = %#04x %#04x, want %#04x %#04x", units[0], units[1], want[0], want[1])
	}
}

func TestStubUnitsForBooleanTrueHighRegister(t *testing.T) {
	units, err := stubUnitsFor("Z", PatchReturnTrue, 3)
	if err != nil {
		t.Fatal(err)
	}
	// v3 → A=3, so word = 0x1000|0x0300|0x0012 = 0x1312; return v3 = 0x030F
	want := []uint16{0x1312, 0x030F}
	if units[0] != want[0] || units[1] != want[1] {
		t.Fatalf("units = %#04x %#04x, want %#04x %#04x", units[0], units[1], want[0], want[1])
	}
}

func TestStubUnitsForBooleanFalse(t *testing.T) {
	units, err := stubUnitsFor("Z", PatchReturnFalse, 2)
	if err != nil {
		t.Fatal(err)
	}
	// const/4 v2,0 = 0x0012|0x0200 = 0x0212 ; return v2
	if units[0] != 0x0212 || units[1] != 0x020F {
		t.Fatalf("units = %#04x %#04x", units[0], units[1])
	}
}

func TestStubUnitsForNullObject(t *testing.T) {
	for _, pt := range []PatchType{PatchReturnTrue, PatchReturnFalse} {
		units, err := stubUnitsFor("Ljava/lang/String;", pt, 0)
		if err != nil {
			t.Fatal(err)
		}
		if units[0] != 0x0012 || units[1] != 0x0011 {
			t.Fatalf("pt=%v units = %#04x %#04x, want const/4-0 + return-object", pt, units[0], units[1])
		}
	}
}

func TestStubUnitsForWideFalse(t *testing.T) {
	units, err := stubUnitsFor("J", PatchReturnFalse, 0)
	if err != nil {
		t.Fatal(err)
	}
	// const-wide/16 v0,0 (op 0x16 low byte) ; return-wide v0 (0x10)
	if len(units) != 3 || units[0] != 0x0016 || units[1] != 0x0000 || units[2] != 0x0010 {
		t.Fatalf("wide-false units = %#04x", units)
	}
}

func TestStubUnitsForMaxInt(t *testing.T) {
	units, err := stubUnitsFor("I", PatchReturnMaxInt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 4 || units[0] != 0x0014 || units[1] != 0xFFFF || units[2] != 0x7FFF || units[3] != 0x000F {
		t.Fatalf("max-int units = %#04x", units)
	}
	// MaxInt on boolean degrades to true (const/4 v0,1 → 0x1012)
	z, err := stubUnitsFor("Z", PatchReturnMaxInt, 0)
	if err != nil || z[0] != 0x1012 {
		t.Fatalf("bool max-int: %#04x %v", z, err)
	}
}

func TestStubUnitsForVoid(t *testing.T) {
	units, err := stubUnitsFor("V", PatchReturnVoid, 5)
	if err != nil || len(units) != 1 || units[0] != 0x000E {
		t.Fatalf("void units = %#04x err=%v", units, err)
	}
}

func TestEnsureScratchLocalGrowsFrameWhenNoLocals(t *testing.T) {
	code := &CodeItem{RegistersSize: 2}
	method := &EncodedMethod{
		AccessFlags: 0,
		ReturnType:  "Z",
		Parameters:  []string{"Ljava/lang/Object;"},
		CodeOff:     8,
		Code:        code,
	}
	data := make([]byte, 64)
	data[method.CodeOff] = 0x02

	reg, err := ensureScratchLocal(data, method)
	if err != nil {
		t.Fatal(err)
	}
	if reg != 0 {
		t.Fatalf("scratch = v%d, want v0", reg)
	}
	if code.RegistersSize != 3 {
		t.Fatalf("registers_size = %d, want grown to 3", code.RegistersSize)
	}
	if data[method.CodeOff] != 0x03 || data[method.CodeOff+1] != 0x00 {
		t.Fatalf("header not updated in image: % x", data[method.CodeOff:method.CodeOff+2])
	}
}

func TestEnsureScratchLocalUsesExistingLocal(t *testing.T) {
	code := &CodeItem{RegistersSize: 4}
	method := &EncodedMethod{
		AccessFlags: accStatic,
		Parameters:  []string{"I"},
		CodeOff:     16,
		Code:        code,
	}
	data := make([]byte, 64)
	data[method.CodeOff] = 0x04

	reg, err := ensureScratchLocal(data, method)
	if err != nil {
		t.Fatal(err)
	}
	if reg != 2 { // locals = 4 - 1 param = 3 → highest local v2
		t.Fatalf("scratch = v%d, want v2", reg)
	}
	if code.RegistersSize != 4 {
		t.Fatalf("frame must not grow when a local exists")
	}
}

func TestParamRegisterCountWideParams(t *testing.T) {
	m := &EncodedMethod{
		AccessFlags: accStatic,
		Parameters:  []string{"J", "I", "D"},
	}
	if got := paramRegisterCount(m); got != 5 { // 2+1+2
		t.Fatalf("paramRegisterCount = %d, want 5", got)
	}
	instance := &EncodedMethod{AccessFlags: 0, Parameters: []string{}}
	if got := paramRegisterCount(instance); got != 1 {
		t.Fatalf("this should occupy 1 register, got %d", got)
	}
}

func TestTrySynthesizeStubRejectsMultiOpPlans(t *testing.T) {
	plan := &PatchPlan{Ops: []PatchOp{{Type: PatchReturnTrue}, {Type: PatchNop}}}
	m := &EncodedMethod{ReturnType: "Z"}
	if _, ok, _ := trySynthesizeStub(m, plan, 0); ok {
		t.Fatal("multi-op plan must fall through to full pipeline")
	}
	single := &PatchPlan{Ops: []PatchOp{{Type: PatchBypassLicense}}}
	units, ok, err := trySynthesizeStub(&EncodedMethod{ReturnType: "Z"}, single, 0)
	if !ok || err != nil || units[0] != 0x1012 {
		t.Fatalf("alias op not mapped to true-stub: ok=%v units=%#04x err=%v", ok, units, err)
	}
}
