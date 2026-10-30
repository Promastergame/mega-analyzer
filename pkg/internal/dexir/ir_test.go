package dexir

import (
	"reflect"
	"testing"
)

func TestOpcodeNamesRoundTrip(t *testing.T) {
	for op, name := range opcodeNames {
		if op.Name() != name {
			t.Errorf("opcode %x name=%q", op, op.Name())
		}
		if got, ok := OpcodeFromName(name); !ok || got != op {
			t.Errorf("lookup %q=%x,%v want %x", name, got, ok, op)
		}
	}
	if got := Opcode(0xff).Name(); got != "op-ff" {
		t.Fatalf("unknown=%q", got)
	}
	if _, ok := OpcodeFromName("not-an-opcode"); ok {
		t.Fatal("unknown name accepted")
	}
}

func TestInstructionKindsAndTargets(t *testing.T) {
	branches := map[Opcode]bool{OpGoto: true, OpGoto16: true, OpGoto32: true, OpPackedSwitch: true, OpSparseSwitch: true}
	for op := OpIfEq; op <= OpIfLez; op++ {
		branches[op] = true
	}
	for n := 0; n < 256; n++ {
		op := Opcode(n)
		ins := &Instruction{Op: op}
		if ins.IsBranch() != branches[op] {
			t.Errorf("branch classification %x", op)
		}
		wantInvoke := (n >= 0x6e && n <= 0x72) || (n >= 0x74 && n <= 0x78)
		if ins.IsInvoke() != wantInvoke {
			t.Errorf("invoke classification %x", op)
		}
		if ins.IsReturn() != (n >= 0x0e && n <= 0x11) {
			t.Errorf("return classification %x", op)
		}
	}
	for _, op := range []Opcode{OpPackedSwitchPayload, OpSparseSwitchPayload, OpFillArrayDataPayload} {
		if !(&Instruction{Op: op}).IsPayload() {
			t.Errorf("payload %x", op)
		}
	}
	if (&Instruction{Op: OpNop}).IsPayload() {
		t.Fatal("nop is not payload")
	}
	ins := &Instruction{Offset: 10}
	if ins.PayloadTargetAbs(0) != -1 {
		t.Fatal("missing payload")
	}
	ins.Payload = &Payload{Targets: []int32{-4, 7}}
	for i, want := range map[int]int32{-1: -1, 0: 6, 1: 17, 2: -1} {
		if got := ins.PayloadTargetAbs(i); got != want {
			t.Errorf("target %d=%d want %d", i, got, want)
		}
	}
}

func TestRegisterCountAndResolution(t *testing.T) {
	cases := []struct {
		m    Method
		want int
	}{
		{Method{RegistersSize: 9, Locals: 20}, 9},
		{Method{RegistersSize: -1, Locals: 2, Params: []string{"J", "D", "I"}}, 8},
		{Method{RegistersSize: -1, Locals: 2, IsStatic: true, Params: []string{"J", "D", "I"}}, 7},
		{Method{RegistersSize: -1, Locals: -1}, 0},
	}
	for _, tt := range cases {
		if got := tt.m.RegisterCount(); got != tt.want {
			t.Errorf("register count=%d want %d", got, tt.want)
		}
	}
	ResolvePRegisters(nil)
	ResolvePRegisters(&Method{RegistersSize: 0})
	for _, static := range []bool{false, true} {
		ins := &Instruction{Dst: -2, Srcs: []int32{-3, NoRegister, 2}}
		m := &Method{RegistersSize: 8, IsStatic: static, Params: []string{"J", "I"}, Instructions: []*Instruction{nil, ins}}
		base := int32(4)
		if static {
			base = 5
		}
		ResolvePRegisters(m)
		ResolvePRegisters(m)
		if ins.Dst != base || !reflect.DeepEqual(ins.Srcs, []int32{base + 1, NoRegister, 2}) {
			t.Fatalf("resolved=%+v", ins)
		}
	}
}

func TestReferencesAnnotationsAndMethods(t *testing.T) {
	var mr *MethodRef
	var fr *FieldRef
	var a *Annotation
	if mr.String() != "" || fr.String() != "" || a.Get("x") != "" {
		t.Fatal("nil helpers")
	}
	if got := (&MethodRef{Class: "La/B;", Name: "f", Proto: "(I)V"}).String(); got != "La/B;->f(I)V" {
		t.Fatal(got)
	}
	if got := (&FieldRef{Class: "La/B;", Name: "x", Type: "I"}).String(); got != "La/B;->x:I" {
		t.Fatal(got)
	}
	if (&Annotation{}).Get("x") != "" || (&Annotation{Values: map[string]string{"x": "1"}}).Get("x") != "1" {
		t.Fatal("annotation lookup")
	}
	m1 := &Method{Name: "f", Params: []string{"I", "J"}, ReturnType: "V"}
	m2 := &Method{Name: "f", ReturnType: "I"}
	c := &Class{Descriptor: "La/b/C;", Methods: []*Method{{Name: "other"}, m1, m2}}
	if c.ClassName() != "a.b.C" || (&Class{Descriptor: "a/b"}).ClassName() != "a.b" {
		t.Fatal("descriptor normalization")
	}
	if c.FindMethod("f", "") != m1 || c.FindMethod("f", "()I") != m2 || c.FindMethod("f", "()V") != nil || c.FindMethod("missing", "") != nil {
		t.Fatal("overload lookup")
	}
}
