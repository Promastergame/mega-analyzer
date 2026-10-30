package adapters

// Round-trip equivalence: the DEX adapter (binary → IR) and the text
// adapter (generated smali → IR) must agree on the same class.

import (
	"bytes"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
	. "mega-analyzer/pkg/internal/dexir"
)

func TestRoundTripDexVsText(t *testing.T) {
	data := buildIRTestDEX()
	p, err := apkloader.ParseDEXBytes(data)
	if err != nil {
		t.Fatalf("ParseDEXBytes: %v", err)
	}
	cds := p.GetClasses()
	if len(cds) != 1 {
		t.Fatalf("classes = %d, want 1", len(cds))
	}
	smali := string(apkloader.GenerateSmaliClass(cds[0], p))

	dexClasses := FromDEX(p)
	if len(dexClasses) != 1 {
		t.Fatalf("FromDEX classes = %d", len(dexClasses))
	}
	dexCls := dexClasses[0]

	textCls, err := FromSmaliText(smali)
	if err != nil {
		t.Fatalf("FromSmaliText(generated): %v\n--- smali ---\n%s", err, smali)
	}

	// ── Class level ─────────────────────────────────────
	if dexCls.Descriptor != textCls.Descriptor {
		t.Errorf("Descriptor: dex %q vs text %q", dexCls.Descriptor, textCls.Descriptor)
	}
	if dexCls.SuperClass != textCls.SuperClass {
		t.Errorf("SuperClass: dex %q vs text %q", dexCls.SuperClass, textCls.SuperClass)
	}
	if dexCls.SourceFile != textCls.SourceFile {
		t.Errorf("SourceFile: dex %q vs text %q", dexCls.SourceFile, textCls.SourceFile)
	}
	if len(dexCls.Methods) != len(textCls.Methods) {
		t.Fatalf("method count: dex %d vs text %d", len(dexCls.Methods), len(textCls.Methods))
	}

	// ── Method level ────────────────────────────────────
	for i := range dexCls.Methods {
		dm, tm := dexCls.Methods[i], textCls.Methods[i]
		if dm.Name != tm.Name {
			t.Fatalf("method[%d]: dex %q vs text %q", i, dm.Name, tm.Name)
		}
		name := dm.Name
		if dm.RegistersSize != tm.RegistersSize {
			t.Errorf("%s: RegistersSize dex %d vs text %d", name, dm.RegistersSize, tm.RegistersSize)
		}
		if dm.ReturnType != tm.ReturnType {
			t.Errorf("%s: ReturnType dex %q vs text %q", name, dm.ReturnType, tm.ReturnType)
		}
		if dm.IsStatic != tm.IsStatic {
			t.Errorf("%s: IsStatic dex %v vs text %v", name, dm.IsStatic, tm.IsStatic)
		}

		compareOpcodeSequences(t, name, dm.Instructions, tm.Instructions)
		compareStringConsts(t, name, dm.Instructions, tm.Instructions)
		compareMethodRefs(t, name, dm.Instructions, tm.Instructions)
		compareBranchOffsets(t, name, dm, tm)
		comparePayloads(t, name, dm, tm)
		compareTryCatches(t, name, dm, tm)
	}
}

func compareOpcodeSequences(t *testing.T, name string, d, x []*Instruction) {
	t.Helper()
	if len(d) != len(x) {
		t.Errorf("%s: instruction count dex %d vs text %d", name, len(d), len(x))
		return
	}
	for i := range d {
		if d[i].Op != x[i].Op {
			t.Errorf("%s: insn[%d] op dex %s vs text %s", name, i, d[i].Op.Name(), x[i].Op.Name())
		}
	}
}

func compareStringConsts(t *testing.T, name string, d, x []*Instruction) {
	t.Helper()
	for i := range d {
		if d[i].Op != OpConstString && d[i].Op != OpConstStringJumbo {
			continue
		}
		if i >= len(x) || !d[i].HasStr || !x[i].HasStr || d[i].Str != x[i].Str {
			t.Errorf("%s: insn[%d] const-string dex %q vs text %q",
				name, i, d[i].Str, textStrAt(x, i))
		}
		if d[i].Dst != x[i].Dst {
			t.Errorf("%s: insn[%d] const-string dst dex %d vs text %d", name, i, d[i].Dst, x[i].Dst)
		}
	}
}

func textStrAt(x []*Instruction, i int) string {
	if i < len(x) && x[i].HasStr {
		return x[i].Str
	}
	return "<missing>"
}

func compareMethodRefs(t *testing.T, name string, d, x []*Instruction) {
	t.Helper()
	for i := range d {
		if !d[i].IsInvoke() {
			continue
		}
		if i >= len(x) || d[i].Method == nil || x[i].Method == nil {
			t.Errorf("%s: insn[%d] invoke ref missing on text side", name, i)
			continue
		}
		if d[i].Method.String() != x[i].Method.String() {
			t.Errorf("%s: insn[%d] MethodRef dex %s vs text %s",
				name, i, d[i].Method, x[i].Method)
		}
		if d[i].Method.Proto != x[i].Method.Proto {
			t.Errorf("%s: insn[%d] Proto dex %q vs text %q",
				name, i, d[i].Method.Proto, x[i].Method.Proto)
		}
	}
}

// The emitter uses symbolic labels. Text IR intentionally has no bytecode
// layout, so compare target instructions instead of requiring numeric offsets.
func textLabelOffset(dm, tm *Method, name string) (int32, bool) {
	for _, label := range tm.Labels {
		if label.Name != name {
			continue
		}
		for i, ins := range tm.Instructions {
			if ins.Line > label.Line && i < len(dm.Instructions) {
				return int32(dm.Instructions[i].Offset), true
			}
		}
	}
	return 0, false
}

func compareBranchOffsets(t *testing.T, name string, dm, tm *Method) {
	t.Helper()
	d, x := dm.Instructions, tm.Instructions
	for i := range d {
		if !d[i].IsBranch() && d[i].Op != OpFillArrayData {
			continue
		}
		if i >= len(x) {
			t.Errorf("%s: insn[%d] missing on text side", name, i)
			continue
		}
		if x[i].BranchLabel != "" {
			target, ok := textLabelOffset(dm, tm, x[i].BranchLabel)
			if !ok || target != d[i].BranchTarget {
				t.Errorf("%s: insn[%d] target dex %d vs text label %q (%d, resolved=%v)",
					name, i, d[i].BranchTarget, x[i].BranchLabel, target, ok)
			}
		} else if d[i].BranchOffset != x[i].BranchOffset {
			t.Errorf("%s: insn[%d] BranchOffset dex %d vs text %d",
				name, i, d[i].BranchOffset, x[i].BranchOffset)
		}
	}
}

func comparePayloads(t *testing.T, name string, dm, tm *Method) {
	t.Helper()
	d, x := dm.Instructions, tm.Instructions
	for i := range d {
		if d[i].Payload == nil {
			continue
		}
		if i >= len(x) || x[i].Payload == nil {
			t.Errorf("%s: insn[%d] (%s) payload missing on text side", name, i, d[i].Op.Name())
			continue
		}
		dp, xp := d[i].Payload, x[i].Payload
		if dp.Kind != xp.Kind {
			t.Errorf("%s: insn[%d] payload kind dex %v vs text %v", name, i, dp.Kind, xp.Kind)
		}
		if dp.FirstKey != xp.FirstKey {
			t.Errorf("%s: insn[%d] FirstKey dex %d vs text %d", name, i, dp.FirstKey, xp.FirstKey)
		}
		if len(dp.Keys) != len(xp.Keys) {
			t.Errorf("%s: insn[%d] Keys dex %v vs text %v", name, i, dp.Keys, xp.Keys)
		} else {
			for k := range dp.Keys {
				if dp.Keys[k] != xp.Keys[k] {
					t.Errorf("%s: insn[%d] Key[%d] dex %d vs text %d", name, i, k, dp.Keys[k], xp.Keys[k])
				}
			}
		}
		if len(dp.Targets) != len(xp.Targets) {
			t.Errorf("%s: insn[%d] Targets dex %v vs text %v", name, i, dp.Targets, xp.Targets)
		} else {
			for k := range dp.Targets {
				if k < len(xp.TargetLabels) && xp.TargetLabels[k] != "" {
					owner := d[i]
					if owner.IsPayload() {
						for _, candidate := range d {
							if !candidate.IsPayload() && candidate.Payload != nil && candidate.BranchTarget == int32(d[i].Offset) {
								owner = candidate
								break
							}
						}
					}
					target, ok := textLabelOffset(dm, tm, xp.TargetLabels[k])
					want := int32(owner.Offset) + dp.Targets[k]
					if owner.IsPayload() || !ok || target != want {
						t.Errorf("%s: insn[%d] Target[%d] dex %d vs text label %q (%d, resolved=%v)",
							name, i, k, want, xp.TargetLabels[k], target, ok)
					}
				} else if dp.Targets[k] != xp.Targets[k] {
					t.Errorf("%s: insn[%d] Target[%d] dex %d vs text %d", name, i, k, dp.Targets[k], xp.Targets[k])
				}
			}
		}
		if dp.ElemWidth != xp.ElemWidth {
			t.Errorf("%s: insn[%d] ElemWidth dex %d vs text %d", name, i, dp.ElemWidth, xp.ElemWidth)
		}
		if !bytes.Equal(dp.Values, xp.Values) {
			t.Errorf("%s: insn[%d] Values dex %x vs text %x", name, i, dp.Values, xp.Values)
		}
		// Imm carries the relative payload offset for switch/fill-array-data.
		if x[i].BranchLabel == "" && (d[i].Op == OpPackedSwitch || d[i].Op == OpSparseSwitch || d[i].Op == OpFillArrayData) {
			if d[i].Imm != x[i].Imm {
				t.Errorf("%s: insn[%d] Imm dex %d vs text %d", name, i, d[i].Imm, x[i].Imm)
			}
		}
	}
}

func compareTryCatches(t *testing.T, name string, dm, tm *Method) {
	t.Helper()
	if len(dm.TryCatches) != len(tm.TryCatches) {
		t.Errorf("%s: TryCatches dex %d vs text %d", name, len(dm.TryCatches), len(tm.TryCatches))
		return
	}
	for i := range dm.TryCatches {
		dtc, ttc := dm.TryCatches[i], tm.TryCatches[i]
		if dtc.Type != ttc.Type {
			t.Errorf("%s: catch[%d] type dex %q vs text %q", name, i, dtc.Type, ttc.Type)
		}
		if dtc.StartLabel != ttc.StartLabel || dtc.EndLabel != ttc.EndLabel ||
			dtc.HandlerLabel != ttc.HandlerLabel {
			t.Errorf("%s: catch[%d] labels dex [%s..%s]->%s vs text [%s..%s]->%s",
				name, i, dtc.StartLabel, dtc.EndLabel, dtc.HandlerLabel,
				ttc.StartLabel, ttc.EndLabel, ttc.HandlerLabel)
		}
	}
}
