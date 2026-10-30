package apkloader

import (
	"context"
	"testing"
)

func TestClassInitializationOrdersDependencies(t *testing.T) {
	base := ownedMethodForEmulator(1, []uint16{0x1012, 0x0067, 0x0000, 0x000e})
	base.ClassName, base.MethodName, base.ReturnType, base.AccessFlags = "Lx/Base;", "<clinit>", "V", accessFlagStatic
	base.References.Fields[0] = Field{ClassName: "Lx/Base;", FieldName: "N", TypeName: "I"}

	child := ownedMethodForEmulator(2, []uint16{0x0060, 0x0000, 0x0067, 0x0001, 0x000e})
	child.ClassName, child.MethodName, child.ReturnType, child.AccessFlags = "Lx/Child;", "<clinit>", "V", accessFlagStatic
	child.References.Fields[0] = Field{ClassName: "Lx/Base;", FieldName: "N", TypeName: "I"}
	child.References.Fields[1] = Field{ClassName: "Lx/Child;", FieldName: "M", TypeName: "I"}

	initial := NewOwnedStaticResolver(map[string]OwnedStaticValue{
		"Lx/Base;->N:I":  {Kind: StaticIntegral, TypeName: "I"},
		"Lx/Child;->M:I": {Kind: StaticIntegral, TypeName: "I"},
	})
	classes := NewOwnedClassInitResolver([]OwnedClassInit{
		{ClassName: "Lx/Child;", SuperClass: "Lx/Base;", Initializer: child.Descriptor(), Dependencies: []string{"Lx/Base;"}},
		{ClassName: "Lx/Base;", Initializer: base.Descriptor()},
	})
	got := ReconstructStaticFieldsWithClasses(context.Background(), NewOwnedMethodResolver([]OwnedDEXMethod{child, base}), classes, initial, DefaultDalvikEmulatorConfig())
	value, ok := got.Resolver.Resolve("Lx/Child;->M:I")
	if !ok || value.Int64 != 1 {
		t.Fatalf("dependency value not committed: %+v outcomes=%+v metrics=%+v", value, got.Outcomes, got.Metrics)
	}
	if got.Metrics.Initialized != 2 || got.Metrics.CommittedFields != 2 {
		t.Fatalf("unexpected metrics: %+v", got.Metrics)
	}
}

func TestClassInitializationCycleRollsBack(t *testing.T) {
	classes := NewOwnedClassInitResolver([]OwnedClassInit{
		{ClassName: "Lx/A;", Dependencies: []string{"Lx/B;"}},
		{ClassName: "Lx/B;", Dependencies: []string{"Lx/A;"}},
	})
	got := ReconstructStaticFieldsWithClasses(context.Background(), NewOwnedMethodResolver(nil), classes, NewOwnedStaticResolver(nil), DefaultDalvikEmulatorConfig())
	if got.Metrics.Cycles != 1 {
		t.Fatalf("cycle not recorded: %+v", got.Metrics)
	}
	for _, outcome := range got.Outcomes {
		if outcome.State != ClassUnavailable {
			t.Fatalf("cycle member initialized: %+v", outcome)
		}
	}
}

func TestClassInitializerStaticArrayUsesCopyOnWrite(t *testing.T) {
	code := []uint16{
		0x0062, 0x0000, // sget-object v0, field@0
		0x1112,         // const/4 v1, 1
		0x7212,         // const/4 v2, 7
		0x024b, 0x0100, // aput v2, v0, v1
		0x000e,
	}
	clinit := ownedMethodForEmulator(3, code)
	clinit.ClassName, clinit.MethodName, clinit.ReturnType, clinit.AccessFlags = "Lx/K;", "<clinit>", "V", accessFlagStatic
	clinit.References.Fields[0] = Field{ClassName: "Lx/K;", FieldName: "A", TypeName: "[I"}
	initial := NewOwnedStaticResolver(map[string]OwnedStaticValue{
		"Lx/K;->A:[I": {Kind: StaticArray, TypeName: "[I", Elements: []OwnedStaticValue{{Kind: StaticIntegral}, {Kind: StaticIntegral}}},
	})
	classes := NewOwnedClassInitResolver([]OwnedClassInit{{ClassName: "Lx/K;", Initializer: clinit.Descriptor()}})
	got := ReconstructStaticFieldsWithClasses(context.Background(), NewOwnedMethodResolver([]OwnedDEXMethod{clinit}), classes, initial, DefaultDalvikEmulatorConfig())
	value, _ := got.Resolver.Resolve("Lx/K;->A:[I")
	if len(value.Elements) != 2 || value.Elements[1].Int64 != 7 {
		t.Fatalf("array transaction missing: %+v", value)
	}
	original, _ := initial.Resolve("Lx/K;->A:[I")
	if original.Elements[1].Int64 != 0 {
		t.Fatalf("immutable input mutated: %+v", original)
	}
}
