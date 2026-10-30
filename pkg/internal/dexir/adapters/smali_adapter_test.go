package adapters

import (
	"bytes"
	"testing"

	. "mega-analyzer/pkg/internal/dexir"
)

const smaliTestSource = `.class public Lcom/example/Tx;
.super Ljava/lang/Object;
.source "Tx.java"

.field private name:Ljava/lang/String;

.method public static compute(IJ)I
    .registers 4

    add-int/2addr p0, p2
    add-int/lit8 p1, p0, 0x2a
    return p1
.end method

.method public edgeStrings()V
    .locals 2

    const-string v0, "a, b, \"c\" d"
    const-string v1, "unicode: ünïcode ☺ \u00e9"
    const-string/jumbo v0, ""
    return-void
.end method

.method public flow(ILjava/lang/String;)V
    .locals 3

    :cond_0
    if-eqz p1, :exit

    :try_start_0
    invoke-virtual {p2}, Ljava/lang/String;->length()I
    move-result v0
    :try_end_0

    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    move-exception v1

    packed-switch p1, :pswitch_data_0

    sparse-switch p1, :sswitch_data_0

    fill-array-data v0, :array_0

    :exit
    return-void

    :pswitch_data_0
    .packed-switch 0xa
        0x1
        0x2
    .end packed-switch

    :sswitch_data_0
    .sparse-switch
        0x1 -> 0x3
        0x64 -> -0x2
    .end sparse-switch

    :array_0
    .array-data 2
        0x4241
        0x4443
    .end array-data
.end method
`

func parseTestSmali(t *testing.T) *Class {
	t.Helper()
	cls, err := FromSmaliText(smaliTestSource)
	if err != nil {
		t.Fatalf("FromSmaliText: %v", err)
	}
	return cls
}

func TestSmaliAdapterClassShape(t *testing.T) {
	cls := parseTestSmali(t)

	if cls.Descriptor != "Lcom/example/Tx;" {
		t.Errorf("Descriptor = %q", cls.Descriptor)
	}
	if cls.SuperClass != "Ljava/lang/Object;" {
		t.Errorf("SuperClass = %q", cls.SuperClass)
	}
	if cls.SourceFile != "Tx.java" {
		t.Errorf("SourceFile = %q", cls.SourceFile)
	}
	if len(cls.Fields) != 1 {
		t.Fatalf("Fields = %d, want 1", len(cls.Fields))
	}
	f := cls.Fields[0]
	if f.Name != "name" || f.Type != "Ljava/lang/String;" || f.IsStatic {
		t.Errorf("field = %+v", f)
	}
	if len(cls.Methods) != 3 {
		t.Fatalf("Methods = %d, want 3", len(cls.Methods))
	}
}

func TestSmaliAdapterConstStringEdgeCases(t *testing.T) {
	cls := parseTestSmali(t)
	m := cls.FindMethod("edgeStrings", "")
	if m == nil {
		t.Fatalf("edgeStrings not found")
	}

	var strs []string
	for _, ins := range m.Instructions {
		if ins.Op == OpConstString || ins.Op == OpConstStringJumbo {
			strs = append(strs, ins.Str)
		}
	}
	if len(strs) != 3 {
		t.Fatalf("const-string count = %d, want 3 (got %v)", len(strs), strs)
	}
	if strs[0] != "a, b, \"c\" d" {
		t.Errorf("str[0] = %q (commas/escaped quotes must survive)", strs[0])
	}
	if strs[1] != "unicode: ünïcode ☺ é" {
		t.Errorf("str[1] = %q (unicode + \\uXXXX escapes)", strs[1])
	}
	if strs[2] != "" {
		t.Errorf("str[2] = %q, want empty", strs[2])
	}

	// Registers of the const-string destination.
	first := m.Instructions[0]
	if first.Op != OpConstString || first.Dst != 0 {
		t.Errorf("first insn = %v dst %d", first.Op, first.Dst)
	}
}

func TestSmaliAdapterRegisterCounts(t *testing.T) {
	cls := parseTestSmali(t)

	comp := cls.FindMethod("compute", "")
	if comp == nil {
		t.Fatalf("compute not found")
	}
	if comp.RegistersSize != 4 {
		t.Errorf("compute RegistersSize = %d, want 4", comp.RegistersSize)
	}
	if !comp.IsStatic || comp.RegisterCount() != 4 {
		t.Errorf("compute static/count = %v/%d", comp.IsStatic, comp.RegisterCount())
	}

	flow := cls.FindMethod("flow", "")
	if flow == nil {
		t.Fatalf("flow not found")
	}
	// .locals 3 + params (I=1, String=1) + this = 6.
	if flow.RegistersSize != 6 {
		t.Errorf("flow RegistersSize = %d, want 6 (.locals derivation)", flow.RegistersSize)
	}
	if len(flow.Params) != 2 || flow.Params[0] != "I" || flow.Params[1] != "Ljava/lang/String;" {
		t.Errorf("flow Params = %v", flow.Params)
	}
}

func TestSmaliAdapterResolvePRegisters(t *testing.T) {
	cls := parseTestSmali(t)
	comp := cls.FindMethod("compute", "")

	// Before resolution: p0 encodes as -2, p2 as -4.
	var two *Instruction
	var lit *Instruction
	for _, ins := range comp.Instructions {
		if ins.Op.Name() == "add-int/2addr" {
			two = ins
		}
		if ins.Op.Name() == "add-int/lit8" {
			lit = ins
		}
	}
	if two == nil || lit == nil {
		t.Fatalf("expected add-int/2addr and add-int/lit8, got %v / %v", two, lit)
	}
	if two.Dst != -(0 + 2) {
		t.Errorf("p0 encoding = %d, want -2", two.Dst)
	}
	if two.Srcs[0] != -(0+2) || two.Srcs[1] != -(2+2) {
		t.Errorf("2addr srcs = %v, want [-2 -4]", two.Srcs)
	}

	ResolvePRegisters(comp)

	// static, .registers 4, params I(1)+J(2)=3 → p0 = 1.
	if two.Dst != 1 || two.Srcs[0] != 1 || two.Srcs[1] != 3 {
		t.Errorf("after resolve: dst=%d srcs=%v, want 1 [1 3]", two.Dst, two.Srcs)
	}
	if !lit.HasImm || lit.Imm != 0x2a {
		t.Errorf("lit8 imm = %v %d, want true 0x2a", lit.HasImm, lit.Imm)
	}
	if lit.Dst != 2 || len(lit.Srcs) != 1 || lit.Srcs[0] != 1 {
		t.Errorf("lit8 regs = %d/%v, want 2/[1]", lit.Dst, lit.Srcs)
	}
}

func TestSmaliAdapterBranchLabelsAndCatch(t *testing.T) {
	cls := parseTestSmali(t)
	m := cls.FindMethod("flow", "")

	var br *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpIfEqz {
			br = ins
		}
	}
	if br == nil {
		t.Fatalf("if-eqz not found")
	}
	if br.BranchLabel != "exit" {
		t.Errorf("BranchLabel = %q, want exit", br.BranchLabel)
	}

	labelNames := map[string]bool{}
	for _, l := range m.Labels {
		labelNames[l.Name] = true
	}
	for _, want := range []string{"cond_0", "try_start_0", "try_end_0", "catch_0", "exit"} {
		if !labelNames[want] {
			t.Errorf("label %q missing", want)
		}
	}

	if len(m.TryCatches) != 1 {
		t.Fatalf("TryCatches = %d, want 1", len(m.TryCatches))
	}
	tc := m.TryCatches[0]
	if tc.Type != "Ljava/lang/Exception;" {
		t.Errorf("catch type = %q", tc.Type)
	}
	if tc.StartLabel != "try_start_0" || tc.EndLabel != "try_end_0" || tc.HandlerLabel != "catch_0" {
		t.Errorf("catch labels = %+v", tc)
	}

	var inv *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpInvokeVirtual {
			inv = ins
		}
	}
	if inv == nil || inv.Method == nil {
		t.Fatalf("invoke-virtual not resolved")
	}
	if inv.Method.String() != "Ljava/lang/String;->length()I" {
		t.Errorf("MethodRef = %s", inv.Method)
	}
	var mex *Instruction
	for _, ins := range m.Instructions {
		if ins.Op == OpMoveException {
			mex = ins
		}
	}
	if mex == nil || mex.Dst != 1 {
		t.Fatalf("move-exception dst = %v", mex)
	}
}

func TestSmaliAdapterPayloads(t *testing.T) {
	cls := parseTestSmali(t)
	m := cls.FindMethod("flow", "")

	var packed, sparse, arr *Instruction
	for _, ins := range m.Instructions {
		switch ins.Op {
		case OpPackedSwitch:
			packed = ins
		case OpSparseSwitch:
			sparse = ins
		case OpFillArrayData:
			arr = ins
		}
	}
	if packed == nil || sparse == nil || arr == nil {
		t.Fatalf("switch/fill-array-data instructions missing")
	}

	// Payload pseudo-instructions:
	var packedPl, sparsePl, arrPl *Payload
	for _, ins := range m.Instructions {
		if ins.Payload == nil {
			continue
		}
		switch ins.Op {
		case OpPackedSwitchPayload:
			packedPl = ins.Payload
		case OpSparseSwitchPayload:
			sparsePl = ins.Payload
		case OpFillArrayDataPayload:
			arrPl = ins.Payload
		}
	}
	if packedPl == nil || sparsePl == nil || arrPl == nil {
		t.Fatalf("payload pseudo-instructions missing")
	}

	if packedPl.FirstKey != 0xa || len(packedPl.Targets) != 2 ||
		packedPl.Targets[0] != 1 || packedPl.Targets[1] != 2 {
		t.Errorf("packed payload = firstKey %d targets %v", packedPl.FirstKey, packedPl.Targets)
	}
	if len(sparsePl.Keys) != 2 || sparsePl.Keys[0] != 1 || sparsePl.Keys[1] != 0x64 {
		t.Errorf("sparse keys = %v", sparsePl.Keys)
	}
	if len(sparsePl.Targets) != 2 || sparsePl.Targets[0] != 3 || sparsePl.Targets[1] != -2 {
		t.Errorf("sparse targets = %v", sparsePl.Targets)
	}
	if arrPl.ElemWidth != 2 || !bytes.Equal(arrPl.Values, []byte{0x41, 0x42, 0x43, 0x44}) {
		t.Errorf("array payload = width %d values %x", arrPl.ElemWidth, arrPl.Values)
	}

	// Branch labels on the switch instructions reference the payload tables.
	if packed.BranchLabel != "pswitch_data_0" {
		t.Errorf("packed label = %q", packed.BranchLabel)
	}
	if arr.BranchLabel != "array_0" {
		t.Errorf("fill-array-data label = %q", arr.BranchLabel)
	}
}
