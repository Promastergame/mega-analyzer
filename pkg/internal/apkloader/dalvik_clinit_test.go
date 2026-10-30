package apkloader

import (
	"context"
	"testing"
)

func TestReconstructStaticFieldsCommitsClinitTransaction(t *testing.T) {
	code := []uint16{
		0x7112,         // const/4 v1, 7
		0x0167, 0x0000, // sput v1, field@0
		0x000e, // return-void
	}
	clinit := ownedMethodForEmulator(2, code)
	clinit.ClassName = "Lx/K;"
	clinit.MethodName = "<clinit>"
	clinit.ReturnType = "V"
	clinit.AccessFlags = accessFlagStatic
	clinit.References.Fields[0] = Field{ClassName: "Lx/K;", FieldName: "N", TypeName: "I"}
	initial := NewOwnedStaticResolver(map[string]OwnedStaticValue{"Lx/K;->N:I": {Kind: StaticIntegral, TypeName: "I"}})
	got := ReconstructStaticFields(context.Background(), NewOwnedMethodResolver([]OwnedDEXMethod{clinit}), initial, DefaultDalvikEmulatorConfig())
	value, ok := got.Resolve("Lx/K;->N:I")
	if !ok || value.Int64 != 7 || !value.Transformed {
		t.Fatalf("clinit transaction missing: %+v, %v", value, ok)
	}
}

func TestReconstructStaticFieldsRollsBackAbstainedClinit(t *testing.T) {
	code := []uint16{
		0x7112,
		0x0167, 0x0000,
		0x001d, // monitor-enter v0 -> unsupported
		0x000e,
	}
	clinit := ownedMethodForEmulator(2, code)
	clinit.ClassName = "Lx/K;"
	clinit.MethodName = "<clinit>"
	clinit.ReturnType = "V"
	clinit.AccessFlags = accessFlagStatic
	clinit.References.Fields[0] = Field{ClassName: "Lx/K;", FieldName: "N", TypeName: "I"}
	initial := NewOwnedStaticResolver(map[string]OwnedStaticValue{"Lx/K;->N:I": {Kind: StaticIntegral, TypeName: "I", Int64: 1}})
	got := ReconstructStaticFields(context.Background(), NewOwnedMethodResolver([]OwnedDEXMethod{clinit}), initial, DefaultDalvikEmulatorConfig())
	value, _ := got.Resolve("Lx/K;->N:I")
	if value.Int64 != 1 {
		t.Fatalf("partial clinit write committed: %+v", value)
	}
}
