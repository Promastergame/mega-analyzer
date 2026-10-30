package apkloader

import (
	"context"
	"strings"
	"testing"
)

func TestDalvikStaticStringFeedsInterproceduralRecovery(t *testing.T) {
	calleeCode := []uint16{
		0x0062, 0x0000, // sget-object v0, field@0
		0x206e, 0x0000, 0x0010, // invoke-virtual {v0,v1}, concat
		0x000c,
		0x0011,
	}
	callee := ownedMethodForEmulator(2, calleeCode)
	callee.ClassName = "Lx/H;"
	callee.MethodName = "decode"
	callee.Parameters = []string{"Ljava/lang/String;"}
	callee.ReturnType = "Ljava/lang/String;"
	callee.AccessFlags = accessFlagStatic
	callee.InsSize = 1
	callee.Code.InsSize = 1
	callee.References.Fields[0] = Field{ClassName: "Lx/K;", FieldName: "PREFIX", TypeName: "Ljava/lang/String;"}
	callee.References.Methods[0] = Method{ClassName: "Ljava/lang/String;", MethodName: "concat", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/String;"}
	callee.InvokeArgs = map[uint32][]uint16{2: {0, 1}}

	callerCode := []uint16{0x001a, 0x0000, 0x1071, 0x0000, 0x0000, 0x010c, 0x0111}
	caller := ownedMethodForEmulator(2, callerCode)
	caller.References.Strings[0] = "c2.example"
	caller.References.Methods[0] = Method{ClassName: callee.ClassName, MethodName: callee.MethodName, Parameters: callee.Parameters, ReturnType: callee.ReturnType}
	caller.InvokeArgs = map[uint32][]uint16{2: {0}}
	statics := NewOwnedStaticResolver(map[string]OwnedStaticValue{
		"Lx/K;->PREFIX:Ljava/lang/String;": {Kind: StaticString, TypeName: "Ljava/lang/String;", String: "https://", Operations: []string{"dex-encoded-value:Lx/K;->PREFIX"}},
	})
	got := EmulateOwnedMethodWithEnvironment(context.Background(), caller, NewOwnedMethodResolver([]OwnedDEXMethod{callee}), statics, DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationRecovered || len(got.RecoveredValues) != 1 || got.RecoveredValues[0].Value != "https://c2.example" {
		t.Fatalf("static recovery failed: %+v", got)
	}
	if !strings.Contains(strings.Join(got.RecoveredValues[0].Operations, "\n"), "static-read:Lx/K;->PREFIX") {
		t.Fatalf("missing static provenance: %+v", got.RecoveredValues[0])
	}
}

func TestDalvikStaticWriteAbstainsOutsideClinit(t *testing.T) {
	method := ownedMethodForEmulator(1, []uint16{0x0012, 0x0067, 0x0000, 0x000e})
	method.References.Fields[0] = Field{ClassName: "Lx/K;", FieldName: "N", TypeName: "I"}
	got := EmulateOwnedMethodWithEnvironment(context.Background(), method, nil, NewOwnedStaticResolver(nil), DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationAbstained || !strings.Contains(got.StopReason, "<clinit>") {
		t.Fatalf("static write was not rejected: %+v", got)
	}
}
