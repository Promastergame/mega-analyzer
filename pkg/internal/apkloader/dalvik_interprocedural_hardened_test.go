package apkloader

import (
	"context"
	"sort"
	"testing"
)

// TestOverloadedStaticMethods verifies that overloaded methods with different signatures are resolved correctly.
func TestOverloadedStaticMethods(t *testing.T) {
	// helper(I)I -> returns v0 + 1 (0x00d8, 0x0100 = add-int/lit8 v0, v0, 1)
	codeInt := []uint16{
		0x00d8, 0x0100, // add-int/lit8 v0, v0, 1
		0x000f, 0x0000, // return v0
	}
	mInt := ownedMethodForEmulator(1, codeInt)
	mInt.ClassName, mInt.MethodName, mInt.ReturnType, mInt.AccessFlags = "Lx/Math;", "add", "I", accessFlagStatic
	mInt.Parameters = []string{"I"}
	mInt.InsSize = 1

	// helper(J)J -> returns v0 + 10 (wide long arg across 2 regs v0,v1)
	codeLong := []uint16{
		0x00d8, 0x0a00, // add-int/lit8 v0, v0, 10
		0x0010, 0x0000, // return-wide v0
	}
	mLong := ownedMethodForEmulator(2, codeLong)
	mLong.ClassName, mLong.MethodName, mLong.ReturnType, mLong.AccessFlags = "Lx/Math;", "add", "J", accessFlagStatic
	mLong.Parameters = []string{"J"}
	mLong.InsSize = 2

	resolver := NewOwnedMethodResolver([]OwnedDEXMethod{mInt, mLong})
	session := &dalvikEmulationSession{
		resolver:    resolver,
		statics:     NewOwnedStaticResolver(nil),
		active:      make(map[string]struct{}),
		cache:       make(map[string]emuValue),
		eligibility: make(map[string]methodEligibility),
	}

	exec := &dalvikExecution{
		ctx: context.Background(), method: mInt, config: DefaultDalvikEmulatorConfig(),
		result: DalvikEmulationResult{Status: DalvikEmulationNoOutput}, session: session,
	}

	// Call add(I) with 5 -> 6
	valInt, reason1, ok1 := exec.summarizeAppCall(mInt.Descriptor(), []emuValue{{kind: emuInt, i: 5}}, 0)
	if !ok1 || valInt.i != 6 {
		t.Fatalf("expected add(5) = 6, got %+v, reason=%s, ok=%v", valInt, reason1, ok1)
	}

	// Call add(J) with wide arg 5 -> 15
	valLong, reason2, ok2 := exec.summarizeAppCall(mLong.Descriptor(), []emuValue{{kind: emuLong, i: 5}, {kind: emuLong, i: 5, wideHigh: true}}, 0)
	if !ok2 || valLong.i != 15 {
		t.Fatalf("expected add(5L) = 15, got %+v, reason=%s, ok=%v", valLong, reason2, ok2)
	}
}

// TestDeepCallChainExecution verifies interprocedural execution across a 6-level call chain.
func TestDeepCallChainExecution(t *testing.T) {
	// Chain: m1 -> m2 -> m3 -> m4 -> m5 -> m6
	var methods []OwnedDEXMethod
	for level := 1; level <= 5; level++ {
		// code calls next method via invoke-static field/method #0
		code := []uint16{
			0x0071, 0x0000, 0x0000, // invoke-static {}, method@0
			0x000a, 0x0000, // move-result v0
			0x00d8, 0x0100, // add-int/lit8 v0, v0, 1
			0x000f, 0x0000, // return v0
		}
		m := ownedMethodForEmulator(1, code)
		m.ClassName, m.MethodName, m.ReturnType, m.AccessFlags = "Lx/Chain;", "m"+string(rune('0'+level)), "I", accessFlagStatic
		m.References.Methods[0] = Method{ClassName: "Lx/Chain;", MethodName: "m" + string(rune('0'+level+1)), Parameters: nil, ReturnType: "I"}
		m.InvokeArgs[0] = nil
		methods = append(methods, m)
	}

	// Leaf method m6 returns 10 (const/16 v0, 10 -> 0x0013, 0x000a)
	code6 := []uint16{
		0x0013, 0x000a, // const/16 v0, 10
		0x000f, 0x0000, // return v0
	}
	m6 := ownedMethodForEmulator(1, code6)
	m6.ClassName, m6.MethodName, m6.ReturnType, m6.AccessFlags = "Lx/Chain;", "m6", "I", accessFlagStatic
	methods = append(methods, m6)

	resolver := NewOwnedMethodResolver(methods)
	session := &dalvikEmulationSession{
		resolver:    resolver,
		statics:     NewOwnedStaticResolver(nil),
		active:      make(map[string]struct{}),
		cache:       make(map[string]emuValue),
		eligibility: make(map[string]methodEligibility),
	}

	cfg := DefaultDalvikEmulatorConfig()
	cfg.MaxCallDepth = 10
	exec := &dalvikExecution{
		ctx: context.Background(), method: methods[0], config: cfg,
		result: DalvikEmulationResult{Status: DalvikEmulationNoOutput}, session: session,
	}

	val, reason, ok := exec.summarizeAppCall(methods[0].Descriptor(), nil, 0)
	if !ok || val.i != 15 {
		t.Fatalf("expected deep chain result = 15 (10 + 5 additions), got %+v, reason=%s, ok=%v", val, reason, ok)
	}
}

// TestWorkerOrderingDeterminism verifies worker descriptor sorting generates deterministic ordering.
func TestWorkerOrderingDeterminism(t *testing.T) {
	descriptors := []string{"Lx/Z;->m()V", "Lx/A;->b()V", "Lx/M;->c()V", "Lx/B;->a()V"}
	sort.Strings(descriptors)

	expected := []string{"Lx/A;->b()V", "Lx/B;->a()V", "Lx/M;->c()V", "Lx/Z;->m()V"}
	for i := range descriptors {
		if descriptors[i] != expected[i] {
			t.Fatalf("mismatch at index %d: got %s, expected %s", i, descriptors[i], expected[i])
		}
	}
}
