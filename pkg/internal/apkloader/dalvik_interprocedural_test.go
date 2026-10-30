package apkloader

import (
	"context"
	"strings"
	"testing"
)

func TestDalvikInterproceduralStaticStringSummary(t *testing.T) {
	calleeCode := []uint16{
		0x001a, 0x0000, // const-string v0, string@0
		0x206e, 0x0000, 0x0002, // invoke-virtual {v2,v0}, concat
		0x010c, // move-result-object v1
		0x0111, // return-object v1
	}
	callee := ownedMethodForEmulator(3, calleeCode)
	callee.MethodIdx = 1
	callee.ClassName = "Lx/Helper;"
	callee.MethodName = "decode"
	callee.Parameters = []string{"Ljava/lang/String;"}
	callee.ReturnType = "Ljava/lang/String;"
	callee.AccessFlags = accessFlagStatic
	callee.InsSize = 1
	callee.Code.InsSize = 1
	callee.References.Strings[0] = ".example"
	callee.References.Methods[0] = Method{ClassName: "Ljava/lang/String;", MethodName: "concat", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/String;"}
	callee.InvokeArgs = map[uint32][]uint16{2: {2, 0}}

	callerCode := []uint16{
		0x001a, 0x0000, // const-string v0, string@0
		0x1071, 0x0000, 0x0000, // invoke-static {v0}, helper@0
		0x010c, // move-result-object v1
		0x0111, // return-object v1
	}
	caller := ownedMethodForEmulator(2, callerCode)
	caller.ClassName = "Lx/Caller;"
	caller.MethodName = "endpoint"
	caller.ReturnType = "Ljava/lang/String;"
	caller.References.Strings[0] = "c2"
	caller.References.Methods[0] = Method{ClassName: callee.ClassName, MethodName: callee.MethodName, Parameters: callee.Parameters, ReturnType: callee.ReturnType}
	caller.InvokeArgs = map[uint32][]uint16{2: {0}}

	got := EmulateOwnedMethodWithResolver(context.Background(), caller, NewOwnedMethodResolver([]OwnedDEXMethod{callee}), DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationRecovered || len(got.RecoveredValues) != 1 || got.RecoveredValues[0].Value != "c2.example" {
		t.Fatalf("unexpected interprocedural result: %+v", got)
	}
	if !strings.Contains(strings.Join(got.RecoveredValues[0].Operations, "\n"), "app-call:Lx/Helper;->decode") {
		t.Fatalf("missing call provenance: %+v", got.RecoveredValues[0])
	}
}

func TestDalvikInterproceduralProducesTypedProof(t *testing.T) {
	callee := ownedMethodForEmulator(2, []uint16{0x001a, 0x0000, 0x0011})
	callee.ClassName, callee.MethodName, callee.ReturnType, callee.AccessFlags = "Lx/P;", "value", "Ljava/lang/String;", accessFlagStatic
	callee.References.Strings[0] = "proof.example"
	caller := ownedMethodForEmulator(1, []uint16{0x0071, 0x0000, 0x0000, 0x000c, 0x0011})
	caller.References.Methods[0] = Method{ClassName: callee.ClassName, MethodName: callee.MethodName, ReturnType: callee.ReturnType}
	got := EmulateOwnedMethodWithResolver(context.Background(), caller, NewOwnedMethodResolver([]OwnedDEXMethod{callee}), DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationRecovered || len(got.CallProofs) != 1 || got.CallProofs[0].Status != "completed" || got.CallProofs[0].Digest == "" {
		t.Fatalf("typed proof missing: %+v", got)
	}
	if got.CallMetrics.Attempts != 1 || got.CallMetrics.Completed != 1 {
		t.Fatalf("call counters missing: %+v", got.CallMetrics)
	}
}

func TestBindStaticArgumentsAcceptsValidatedWidePair(t *testing.T) {
	method := OwnedDEXMethod{ClassName: "Lx/W;", MethodName: "wide", Parameters: []string{"J"}, ReturnType: "J", RegistersSize: 3, InsSize: 2, AccessFlags: accessFlagStatic}
	low := intValue(0x1122334455667788, true, "", false)
	registers, reason, ok := bindStaticArguments(method, []emuValue{low, low})
	if !ok || reason != "" || registers[1].kind != emuLong || !registers[2].wideHigh {
		t.Fatalf("wide pair rejected: %s %+v", reason, registers)
	}
}

func TestBindStaticArgumentsRejectsMalformedWidePair(t *testing.T) {
	method := OwnedDEXMethod{ClassName: "Lx/W;", MethodName: "wide", Parameters: []string{"J"}, ReturnType: "J", RegistersSize: 2, InsSize: 2, AccessFlags: accessFlagStatic}
	low := intValue(7, true, "", false)
	if _, _, ok := bindStaticArguments(method, []emuValue{low, intValue(8, true, "", false)}); ok {
		t.Fatal("malformed wide pair accepted")
	}
}

func TestDalvikInterproceduralRecursionAbstains(t *testing.T) {
	code := []uint16{
		0x1071, 0x0000, 0x0000, // invoke-static {v0}, self@0
		0x000c,
		0x0011,
	}
	method := ownedMethodForEmulator(1, code)
	method.ClassName = "Lx/R;"
	method.MethodName = "loop"
	method.Parameters = []string{"Ljava/lang/String;"}
	method.ReturnType = "Ljava/lang/String;"
	method.AccessFlags = accessFlagStatic
	method.InsSize = 1
	method.Code.InsSize = 1
	method.References.Methods[0] = Method{ClassName: method.ClassName, MethodName: method.MethodName, Parameters: method.Parameters, ReturnType: method.ReturnType}
	method.InvokeArgs = map[uint32][]uint16{0: {0}}

	callerCode := []uint16{0x001a, 0x0000, 0x1071, 0x0000, 0x0000, 0x010c, 0x0111}
	caller := ownedMethodForEmulator(2, callerCode)
	caller.References.Strings[0] = "seed"
	caller.References.Methods[0] = method.References.Methods[0]
	caller.InvokeArgs = map[uint32][]uint16{2: {0}}
	got := EmulateOwnedMethodWithResolver(context.Background(), caller, NewOwnedMethodResolver([]OwnedDEXMethod{method}), DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationAbstained || (!strings.Contains(got.StopReason, "recursive") && !strings.Contains(got.StopReason, "eligibility cycle")) {
		t.Fatalf("recursion was not rejected: %+v", got)
	}
}
