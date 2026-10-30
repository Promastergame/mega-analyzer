package apkloader

import (
	"context"
	"reflect"
	"testing"
)

func ownedMethodForEmulator(registers uint16, code []uint16) OwnedDEXMethod {
	return OwnedDEXMethod{
		ClassName: "Lx/D;", MethodName: "decrypt", RegistersSize: registers,
		CodeUnits: code, RawInsns: DecodeMethodIR(code, nil),
		Code:       &CodeItem{RegistersSize: registers, InsnsSize: uint32(len(code))},
		References: DEXReferenceSnapshot{Strings: map[uint32]string{}, Types: map[uint32]string{}, Methods: map[uint32]Method{}, Fields: map[uint32]Field{}},
		InvokeArgs: map[uint32][]uint16{},
	}
}

func TestDalvikEmulatorRecoversStringBuilderOutput(t *testing.T) {
	code := []uint16{
		0x0022, 0x0000, // new-instance v0, type@0
		0x1070, 0x0000, 0x0000, // invoke-direct {v0}, method@0
		0x011a, 0x0000, // const-string v1, string@0
		0x206e, 0x0001, 0x0010, // invoke-virtual {v0,v1}, method@1
		0x020c,                 // move-result-object v2
		0x106e, 0x0002, 0x0002, // invoke-virtual {v2}, method@2
		0x030c, // move-result-object v3
		0x0311, // return-object v3
	}
	method := ownedMethodForEmulator(4, code)
	method.References.Strings[0] = "https://c2.example"
	method.References.Types[0] = "Ljava/lang/StringBuilder;"
	method.References.Methods[0] = Method{ClassName: "Ljava/lang/StringBuilder;", MethodName: "<init>", ReturnType: "V"}
	method.References.Methods[1] = Method{ClassName: "Ljava/lang/StringBuilder;", MethodName: "append", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/StringBuilder;"}
	method.References.Methods[2] = Method{ClassName: "Ljava/lang/StringBuilder;", MethodName: "toString", ReturnType: "Ljava/lang/String;"}
	method.InvokeArgs = map[uint32][]uint16{2: {0}, 7: {0, 1}, 11: {2}}

	got := EmulateOwnedMethod(context.Background(), method, DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationRecovered || len(got.RecoveredValues) != 1 || got.RecoveredValues[0].Value != "https://c2.example" {
		t.Fatalf("unexpected result: %+v", got)
	}
	again := EmulateOwnedMethod(context.Background(), method, DefaultDalvikEmulatorConfig())
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("non-deterministic result:\n%+v\n%+v", got, again)
	}
}

func TestProcessOwnedMethodRecoveryDoesNotClaimTransformation(t *testing.T) {
	code := []uint16{
		0x0022, 0x0000,
		0x1070, 0x0000, 0x0000,
		0x011a, 0x0000,
		0x206e, 0x0001, 0x0010,
		0x020c,
		0x106e, 0x0002, 0x0002,
		0x030c,
		0x0311,
	}
	method := ownedMethodForEmulator(4, code)
	method.References.Strings[0] = "secret.example"
	method.References.Types[0] = "Ljava/lang/StringBuilder;"
	method.References.Methods[0] = Method{ClassName: "Ljava/lang/StringBuilder;", MethodName: "<init>", ReturnType: "V"}
	method.References.Methods[1] = Method{ClassName: "Ljava/lang/StringBuilder;", MethodName: "append", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/StringBuilder;"}
	method.References.Methods[2] = Method{ClassName: "Ljava/lang/StringBuilder;", MethodName: "toString", ReturnType: "Ljava/lang/String;"}
	method.InvokeArgs = map[uint32][]uint16{2: {0}, 7: {0, 1}, 11: {2}}
	cfg := DefaultPipelineConfig()
	cfg.EnableConstantPropagation = false
	cfg.EnableDeadCodeElimination = false
	cfg.EnableOpaquePredicateRemoval = false
	cfg.EnablePatternSimplification = false
	result, err := NewDeobfuscationPipeline(cfg).ProcessOwnedMethod(context.Background(), method)
	if err != nil {
		t.Fatal(err)
	}
	if result.Transformed {
		t.Fatalf("recovery was mislabeled as structural transformation: %+v", result)
	}
	if len(result.RecoveredValues) != 1 || result.Emulation.Status != DalvikEmulationRecovered {
		t.Fatalf("recovery missing from owned result: %+v", result)
	}
}

func TestDalvikEmulatorDoesNotPublishUntouchedLiteral(t *testing.T) {
	code := []uint16{0x001a, 0x0000, 0x0011}
	method := ownedMethodForEmulator(1, code)
	method.References.Strings[0] = "cleartext"
	got := EmulateOwnedMethod(context.Background(), method, DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationNoOutput || len(got.RecoveredValues) != 0 {
		t.Fatalf("untouched literal published: %+v", got)
	}
}

func TestDalvikEmulatorAbstainsOnUnknownArgumentBranch(t *testing.T) {
	code := []uint16{0x0038, 0x0002, 0x0012, 0x000f}
	method := ownedMethodForEmulator(1, code)
	got := EmulateOwnedMethod(context.Background(), method, DefaultDalvikEmulatorConfig())
	if got.Status != DalvikEmulationAbstained || len(got.RecoveredValues) != 0 {
		t.Fatalf("unknown branch was guessed: %+v", got)
	}
}

func TestDalvikEmulatorHonorsCancellationAndLoopBudget(t *testing.T) {
	method := ownedMethodForEmulator(1, []uint16{0x0028}) // goto +0
	cfg := DefaultDalvikEmulatorConfig()
	cfg.MaxVisitsPerOffset = 2
	got := EmulateOwnedMethod(context.Background(), method, cfg)
	if got.Status != DalvikEmulationBudgetExhausted {
		t.Fatalf("loop budget not enforced: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = EmulateOwnedMethod(ctx, method, cfg)
	if got.Status != DalvikEmulationCancelled {
		t.Fatalf("cancellation not honored: %+v", got)
	}
}

func TestDecodeOwnedFillArrayAndMalformedPayload(t *testing.T) {
	code := []uint16{0x0026, 0x0003, 0x0000, 0x0000, 0x0300, 0x0001, 0x0003, 0x0000, 0x4241, 0x0043}
	values, err := decodeOwnedFillArray(code, 0, 4, 8)
	if err != nil || !reflect.DeepEqual(values, []int64{65, 66, 67}) {
		t.Fatalf("decoded %v, err=%v", values, err)
	}
	if _, err := decodeOwnedFillArray(code[:8], 0, 4, 8); err == nil {
		t.Fatal("truncated payload accepted")
	}
}
