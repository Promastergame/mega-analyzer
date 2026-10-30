package apkloader

import (
	"context"
	"testing"
)

// TestClinitSuperclassInitializationOrder verifies superclass <clinit> executes before child.
func TestClinitSuperclassInitializationOrder(t *testing.T) {
	// Base class <clinit> sets Lx/Base;->N = 1
	baseCode := []uint16{
		0x1012,         // const/4 v0, 1
		0x0067, 0x0000, // sput v0, Lx/Base;->N:I (field #0)
		0x000e, // return-void
	}
	baseClinit := ownedMethodForEmulator(1, baseCode)
	baseClinit.ClassName, baseClinit.MethodName, baseClinit.ReturnType, baseClinit.AccessFlags = "Lx/Base;", "<clinit>", "V", accessFlagStatic
	baseClinit.References.Fields[0] = Field{ClassName: "Lx/Base;", FieldName: "N", TypeName: "I"}

	// Child class <clinit> reads Lx/Base;->N, sets Lx/Child;->M = 2
	childCode := []uint16{
		0x0060, 0x0000, // sget v0, Lx/Base;->N:I (field #0)
		0x2012,         // const/4 v0, 2
		0x0067, 0x0001, // sput v0, Lx/Child;->M:I (field #1)
		0x000e, // return-void
	}
	childClinit := ownedMethodForEmulator(1, childCode)
	childClinit.ClassName, childClinit.MethodName, childClinit.ReturnType, childClinit.AccessFlags = "Lx/Child;", "<clinit>", "V", accessFlagStatic
	childClinit.References.Fields[0] = Field{ClassName: "Lx/Base;", FieldName: "N", TypeName: "I"}
	childClinit.References.Fields[1] = Field{ClassName: "Lx/Child;", FieldName: "M", TypeName: "I"}

	methods := NewOwnedMethodResolver([]OwnedDEXMethod{baseClinit, childClinit})
	classes := NewOwnedClassInitResolver([]OwnedClassInit{
		{ClassName: "Lx/Base;", Initializer: baseClinit.Descriptor()},
		{ClassName: "Lx/Child;", SuperClass: "Lx/Base;", Initializer: childClinit.Descriptor(), Dependencies: []string{"Lx/Base;"}},
	})
	initial := NewOwnedStaticResolver(map[string]OwnedStaticValue{
		"Lx/Base;->N:I":  {Kind: StaticIntegral, TypeName: "I"},
		"Lx/Child;->M:I": {Kind: StaticIntegral, TypeName: "I"},
	})

	res := ReconstructStaticFieldsWithClasses(context.Background(), methods, classes, initial, DefaultDalvikEmulatorConfig())

	baseVal, ok1 := res.Resolver.Resolve("Lx/Base;->N:I")
	if !ok1 || baseVal.Int64 != 1 {
		t.Fatalf("expected Lx/Base;->N = 1, got %+v, %v outcomes=%+v", baseVal, ok1, res.Outcomes)
	}

	childVal, ok2 := res.Resolver.Resolve("Lx/Child;->M:I")
	if !ok2 || childVal.Int64 != 2 {
		t.Fatalf("expected Lx/Child;->M = 2, got %+v, %v outcomes=%+v", childVal, ok2, res.Outcomes)
	}

	if res.Metrics.Initialized != 2 {
		t.Fatalf("expected 2 initialized classes, got %d", res.Metrics.Initialized)
	}
}

// TestClinitSuperclassFailurePropagates verifies child initialization fails if superclass fails.
func TestClinitSuperclassFailurePropagates(t *testing.T) {
	// Base class <clinit> abstains (throw)
	baseCode := []uint16{
		0x0027, // throw v0
	}
	baseClinit := ownedMethodForEmulator(1, baseCode)
	baseClinit.ClassName, baseClinit.MethodName, baseClinit.ReturnType, baseClinit.AccessFlags = "Lx/BaseBad;", "<clinit>", "V", accessFlagStatic

	childCode := []uint16{
		0x000e, // return-void
	}
	childClinit := ownedMethodForEmulator(1, childCode)
	childClinit.ClassName, childClinit.MethodName, childClinit.ReturnType, childClinit.AccessFlags = "Lx/ChildBad;", "<clinit>", "V", accessFlagStatic

	methods := NewOwnedMethodResolver([]OwnedDEXMethod{baseClinit, childClinit})
	classes := NewOwnedClassInitResolver([]OwnedClassInit{
		{ClassName: "Lx/BaseBad;", Initializer: baseClinit.Descriptor()},
		{ClassName: "Lx/ChildBad;", SuperClass: "Lx/BaseBad;", Initializer: childClinit.Descriptor()},
	})

	res := ReconstructStaticFieldsWithClasses(context.Background(), methods, classes, NewOwnedStaticResolver(nil), DefaultDalvikEmulatorConfig())

	var childOutcome ClassInitializationOutcome
	for _, o := range res.Outcomes {
		if o.ClassName == "Lx/ChildBad;" {
			childOutcome = o
		}
	}
	if childOutcome.State != ClassUnavailable {
		t.Fatalf("expected ChildBad to be unavailable, got %+v", childOutcome)
	}
}

// TestClinitMutualCycleDetection verifies A -> B -> A initialization cycle is caught safely.
func TestClinitMutualCycleDetection(t *testing.T) {
	aClinit := ownedMethodForEmulator(1, []uint16{0x000e})
	aClinit.ClassName, aClinit.MethodName, aClinit.ReturnType, aClinit.AccessFlags = "Lx/ClassA;", "<clinit>", "V", accessFlagStatic

	bClinit := ownedMethodForEmulator(1, []uint16{0x000e})
	bClinit.ClassName, bClinit.MethodName, bClinit.ReturnType, bClinit.AccessFlags = "Lx/ClassB;", "<clinit>", "V", accessFlagStatic

	methods := NewOwnedMethodResolver([]OwnedDEXMethod{aClinit, bClinit})
	classes := NewOwnedClassInitResolver([]OwnedClassInit{
		{ClassName: "Lx/ClassA;", Initializer: aClinit.Descriptor(), Dependencies: []string{"Lx/ClassB;"}},
		{ClassName: "Lx/ClassB;", Initializer: bClinit.Descriptor(), Dependencies: []string{"Lx/ClassA;"}},
	})

	res := ReconstructStaticFieldsWithClasses(context.Background(), methods, classes, NewOwnedStaticResolver(nil), DefaultDalvikEmulatorConfig())

	if res.Metrics.Cycles == 0 {
		t.Fatalf("expected cycle metric > 0, got metrics: %+v", res.Metrics)
	}
}

// TestClinitStaticArrayCopyOnWrite verifies mutating static byte array during <clinit> is COW.
func TestClinitStaticArrayCopyOnWrite(t *testing.T) {
	// Initial static array: Lx/Data;->ARR = [10, 20]
	initial := NewOwnedStaticResolver(map[string]OwnedStaticValue{
		"Lx/Data;->ARR:[I": {
			Kind:     StaticArray,
			TypeName: "[I",
			Elements: []OwnedStaticValue{{Kind: StaticIntegral, Int64: 10}, {Kind: StaticIntegral, Int64: 20}},
		},
	})

	// <clinit> reads ARR, changes ARR[1] = 7, writes to ARR
	clinitCode := []uint16{
		0x0062, 0x0000, // sget-object v0, field@0
		0x1112,         // const/4 v1, 1
		0x7212,         // const/4 v2, 7
		0x024b, 0x0100, // aput v2, v0, v1
		0x000e, // return-void
	}
	clinit := ownedMethodForEmulator(3, clinitCode)
	clinit.ClassName, clinit.MethodName, clinit.ReturnType, clinit.AccessFlags = "Lx/Data;", "<clinit>", "V", accessFlagStatic
	clinit.References.Fields[0] = Field{ClassName: "Lx/Data;", FieldName: "ARR", TypeName: "[I"}

	methods := NewOwnedMethodResolver([]OwnedDEXMethod{clinit})
	classes := NewOwnedClassInitResolver([]OwnedClassInit{
		{ClassName: "Lx/Data;", Initializer: clinit.Descriptor()},
	})

	res := ReconstructStaticFieldsWithClasses(context.Background(), methods, classes, initial, DefaultDalvikEmulatorConfig())

	origVal, _ := initial.Resolve("Lx/Data;->ARR:[I")
	if origVal.Elements[1].Int64 != 20 {
		t.Fatalf("original static snapshot was mutated in-place! expected 20, got %d", origVal.Elements[1].Int64)
	}

	newVal, ok := res.Resolver.Resolve("Lx/Data;->ARR:[I")
	if !ok || len(newVal.Elements) != 2 || newVal.Elements[1].Int64 != 7 {
		t.Fatalf("expected updated array element 1 to be 7, got %+v, %v", newVal, ok)
	}
}
