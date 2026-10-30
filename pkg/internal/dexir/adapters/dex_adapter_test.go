package adapters

import (
	"bytes"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
	. "mega-analyzer/pkg/internal/dexir"
)

func parseTestDEX(t *testing.T) (*apkloader.DEXParser, *Class) {
	t.Helper()
	data := buildIRTestDEX()
	p, err := apkloader.ParseDEXBytes(data)
	if err != nil {
		t.Fatalf("ParseDEXBytes: %v", err)
	}
	classes := FromDEX(p)
	if len(classes) != 1 {
		t.Fatalf("FromDEX returned %d classes, want 1", len(classes))
	}
	return p, classes[0]
}

func TestDEXAdapterClassShape(t *testing.T) {
	_, cls := parseTestDEX(t)

	if cls.Descriptor != "Lcom/test/Ir;" {
		t.Errorf("Descriptor = %q", cls.Descriptor)
	}
	if cls.SuperClass != "Ljava/lang/Object;" {
		t.Errorf("SuperClass = %q", cls.SuperClass)
	}
	if cls.SourceFile != "Ir.java" {
		t.Errorf("SourceFile = %q", cls.SourceFile)
	}
	if cls.ClassName() != "com.test.Ir" {
		t.Errorf("ClassName = %q", cls.ClassName())
	}
	if len(cls.Fields) != 1 {
		t.Fatalf("Fields = %d, want 1", len(cls.Fields))
	}
	f := cls.Fields[0]
	if f.Name != "name" || f.Type != "Ljava/lang/String;" {
		t.Errorf("field = %+v", f)
	}
	if f.IsStatic {
		t.Errorf("instance field marked static")
	}
	if len(cls.Methods) != 3 {
		t.Fatalf("Methods = %d, want 3", len(cls.Methods))
	}
}

func findMethod(t *testing.T, cls *Class, name string) *Method {
	t.Helper()
	for _, m := range cls.Methods {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("method %q not found", name)
	return nil
}

func TestDEXAdapterRegisterCounts(t *testing.T) {
	_, cls := parseTestDEX(t)

	m := findMethod(t, cls, "test")
	if m.RegistersSize != 3 {
		t.Errorf("RegistersSize = %d, want 3", m.RegistersSize)
	}
	if m.InsSize != 1 {
		t.Errorf("InsSize = %d, want 1", m.InsSize)
	}
	if m.Locals != 2 {
		t.Errorf("Locals = %d, want 2 (registers-ins)", m.Locals)
	}
	if m.IsStatic {
		t.Errorf("test() should not be static")
	}
	// Instance method with no declared params: p0 (this) = reg 2.
	if len(m.ParamRegisters) != 1 || m.ParamRegisters[0] != 2 {
		t.Errorf("ParamRegisters = %v, want [2]", m.ParamRegisters)
	}

	init := findMethod(t, cls, "<init>")
	if init.RegistersSize != 1 || init.InsSize != 1 {
		t.Errorf("<init> registers/ins = %d/%d, want 1/1", init.RegistersSize, init.InsSize)
	}
}

func TestDEXAdapterConstStringEdgeCases(t *testing.T) {
	_, cls := parseTestDEX(t)
	m := findMethod(t, cls, "test")

	var cs *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpConstString {
			cs = ins
			break
		}
	}
	if cs == nil {
		t.Fatalf("const-string not found in test()")
	}
	if !cs.HasStr || cs.Str != tdxHelloStr {
		t.Errorf("const-string value = %q, want %q", cs.Str, tdxHelloStr)
	}
	if cs.Dst != 1 {
		t.Errorf("const-string dst = %d, want 1", cs.Dst)
	}
}

func TestDEXAdapterBranchAndLabels(t *testing.T) {
	_, cls := parseTestDEX(t)
	m := findMethod(t, cls, "test")

	var br *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpIfEqz {
			br = ins
			break
		}
	}
	if br == nil {
		t.Fatalf("if-eqz not found")
	}
	if br.BranchOffset != 9 {
		t.Errorf("BranchOffset = %d, want 9", br.BranchOffset)
	}
	if br.BranchTarget != 11 {
		t.Errorf("BranchTarget = %d, want 11", br.BranchTarget)
	}
	if br.BranchLabel == "" {
		t.Errorf("BranchLabel empty, want synthesized label")
	}
	if len(br.Srcs) != 1 || br.Srcs[0] != 1 {
		t.Errorf("if-eqz srcs = %v, want [1]", br.Srcs)
	}
}

func TestDEXAdapterTryCatch(t *testing.T) {
	_, cls := parseTestDEX(t)
	m := findMethod(t, cls, "test")

	if len(m.TryCatches) != 1 {
		t.Fatalf("TryCatches = %d, want 1", len(m.TryCatches))
	}
	tc := m.TryCatches[0]
	if tc.StartOffset != 0 || tc.EndOffset != 11 {
		t.Errorf("try range = [%d..%d), want [0..11)", tc.StartOffset, tc.EndOffset)
	}
	if tc.Type != "" {
		t.Errorf("catch-all Type = %q, want empty", tc.Type)
	}
	if tc.HandlerOffset != 11 {
		t.Errorf("HandlerOffset = %d, want 11", tc.HandlerOffset)
	}
	if tc.StartLabel == "" || tc.EndLabel == "" || tc.HandlerLabel == "" {
		t.Errorf("labels missing: %+v", tc)
	}
	// Handler label must appear in the method label list.
	found := false
	for _, l := range m.Labels {
		if l.Name == tc.HandlerLabel && l.Offset == 11 {
			found = true
		}
	}
	if !found {
		t.Errorf("handler label %q not in Labels", tc.HandlerLabel)
	}
}

func TestDEXAdapterInvokeRef(t *testing.T) {
	_, cls := parseTestDEX(t)
	m := findMethod(t, cls, "test")

	var inv *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpInvokeVirtual {
			inv = ins
			break
		}
	}
	if inv == nil {
		t.Fatalf("invoke-virtual not found")
	}
	if inv.Method == nil {
		t.Fatalf("invoke has no resolved MethodRef")
	}
	mr := inv.Method
	if mr.Class != "Ljava/lang/String;" || mr.Name != "length" {
		t.Errorf("MethodRef = %+v", mr)
	}
	if mr.Proto != "()I" || mr.ReturnType != "I" || len(mr.Params) != 0 {
		t.Errorf("MethodRef proto = %q ret %q params %v", mr.Proto, mr.ReturnType, mr.Params)
	}
	if len(inv.Srcs) != 1 || inv.Srcs[0] != 1 {
		t.Errorf("invoke srcs = %v, want [1]", inv.Srcs)
	}

	// invoke-direct on Object.<init> in <init>().
	init := findMethod(t, cls, "<init>")
	var inv2 *Instruction
	for _, ins := range init.Instructions {
		if ins.Op == OpInvokeDirect {
			inv2 = ins
		}
	}
	if inv2 == nil || inv2.Method == nil {
		t.Fatalf("invoke-direct not resolved in <init>")
	}
	if inv2.Method.Class != "Ljava/lang/Object;" || inv2.Method.Name != "<init>" {
		t.Errorf("invoke-direct ref = %+v", inv2.Method)
	}
	// p0 must be resolved to v-register 0 (registers=1, ins=1).
	if len(inv2.Srcs) != 1 || inv2.Srcs[0] != 0 {
		t.Errorf("invoke-direct srcs = %v, want [0]", inv2.Srcs)
	}
}

func TestDEXAdapterArrayDataPayload(t *testing.T) {
	_, cls := parseTestDEX(t)
	m := findMethod(t, cls, "test")

	var fa *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpFillArrayData {
			fa = ins
			break
		}
	}
	if fa == nil {
		t.Fatalf("fill-array-data not found")
	}
	if fa.Payload == nil {
		t.Fatalf("fill-array-data has no payload")
	}
	pl := fa.Payload
	if pl.Kind != PayloadArrayData {
		t.Errorf("payload kind = %v", pl.Kind)
	}
	if pl.ElemWidth != 2 {
		t.Errorf("ElemWidth = %d, want 2", pl.ElemWidth)
	}
	if !bytes.Equal(pl.Values, []byte("ABCDEF")) {
		t.Errorf("Values = %q, want ABCDEF", pl.Values)
	}

	// The payload pseudo-instruction itself is also materialized.
	hasPseudo := false
	for _, ins := range m.Instructions {
		if ins.Op == OpFillArrayDataPayload && ins.Payload != nil &&
			bytes.Equal(ins.Payload.Values, []byte("ABCDEF")) {
			hasPseudo = true
		}
	}
	if !hasPseudo {
		t.Errorf("payload pseudo-instruction missing")
	}
}

func TestDEXAdapterPackedSwitchPayload(t *testing.T) {
	_, cls := parseTestDEX(t)
	m := findMethod(t, cls, "sw")

	var sw *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpPackedSwitch {
			sw = ins
			break
		}
	}
	if sw == nil {
		t.Fatalf("packed-switch not found")
	}
	if sw.Payload == nil {
		t.Fatalf("packed-switch has no payload")
	}
	pl := sw.Payload
	if pl.Kind != PayloadPackedSwitch {
		t.Errorf("kind = %v", pl.Kind)
	}
	if pl.FirstKey != 10 {
		t.Errorf("FirstKey = %d, want 10", pl.FirstKey)
	}
	if len(pl.Targets) != 2 || pl.Targets[0] != 3 || pl.Targets[1] != 3 {
		t.Errorf("Targets = %v, want [3 3]", pl.Targets)
	}
	// Absolute target = switch offset (0) + 3 = 3 (return-void).
	if got := sw.PayloadTargetAbs(0); got != 3 {
		t.Errorf("PayloadTargetAbs(0) = %d, want 3", got)
	}
	if len(pl.TargetLabels) != 2 || pl.TargetLabels[0] == "" {
		t.Errorf("TargetLabels = %v, want resolved labels", pl.TargetLabels)
	}
	if len(sw.Srcs) != 1 || sw.Srcs[0] != 1 {
		t.Errorf("switch srcs = %v, want [1]", sw.Srcs)
	}
}

func TestDEXAdapterOpcodeNames(t *testing.T) {
	if OpInvokeVirtual.Name() != "invoke-virtual" {
		t.Errorf("name = %q", OpInvokeVirtual.Name())
	}
	op, ok := OpcodeFromName("const-string/jumbo")
	if !ok || op != OpConstStringJumbo {
		t.Errorf("OpcodeFromName(const-string/jumbo) = %v, %v", op, ok)
	}
	if _, ok := OpcodeFromName("not-an-opcode"); ok {
		t.Errorf("unknown opcode should not resolve")
	}
}
