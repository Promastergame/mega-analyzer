package apkloader

import (
	"context"
	"testing"
)

func TestWalkClassOwnedProgressDetachesHyperionInputBeforeLazyRelease(t *testing.T) {
	handler := &CatchHandler{TypeIdx: 1, TypeName: "Ljava/lang/Exception;", HandlerAddr: 7}
	code := &CodeItem{
		RegistersSize: 2,
		InsSize:       1,
		OutsSize:      1,
		InsnsSize:     7,
		Insns: []uint16{
			0x001a, 0x0000, // const-string v0, string@0
			0x1071, 0x0000, 0x0000, // invoke-static {v0}, method@0
			0x000c, // move-result-object v0
			0x0011, // return-object v0
		},
		TriesSize: 1,
		Tries: []*TryItem{{
			StartAddr:     0,
			InsnCount:     5,
			CatchHandlers: []*CatchHandler{handler},
		}},
		Handlers: []*CatchHandler{handler},
	}
	method := &EncodedMethod{
		MethodIdx:   0,
		Name:        "a",
		ClassName:   "Lx/A;",
		ReturnType:  "Ljava/lang/String;",
		Parameters:  []string{"Ljava/lang/String;"},
		AccessFlags: 0x0008,
		Code:        code,
	}
	class := &ClassDef{ClassName: "Lx/A;", DirectMethods: []*EncodedMethod{method}}
	parser := &DEXParser{
		lazyCode: true,
		strings:  []string{"ciphertext"},
		methods: []*Method{{
			ClassName:  "Lx/A;",
			MethodName: "decode",
			ReturnType: "Ljava/lang/String;",
			Parameters: []string{"Ljava/lang/String;"},
		}},
		classes: []*ClassDef{class},
	}

	var owned DEXClassIR
	err := parser.WalkClassOwnedProgress(context.Background(), OwnedDEXOptions{
		EnableHyperion:    true,
		MinCandidateScore: 2,
	}, func(unit DEXClassIR) error {
		owned = unit
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("WalkClassOwnedProgress failed: %v", err)
	}
	if method.Code != nil {
		t.Fatal("lazy parser retained method code after class visitor")
	}
	if len(owned.Methods) != 1 {
		t.Fatalf("owned candidate methods = %d, want 1", len(owned.Methods))
	}

	got := owned.Methods[0]
	if got.CandidateScore < 2 {
		t.Fatalf("candidate score = %d, want >= 2", got.CandidateScore)
	}
	if got.References.Strings[0] != "ciphertext" {
		t.Fatalf("resolved string = %q, want ciphertext", got.References.Strings[0])
	}
	if got.References.Methods[0].MethodName != "decode" {
		t.Fatalf("resolved method = %q, want decode", got.References.Methods[0].MethodName)
	}
	if len(got.InvokeArgs[2]) != 1 || got.InvokeArgs[2][0] != 0 {
		t.Fatalf("invoke args at pc 2 = %v, want [0]", got.InvokeArgs[2])
	}
	if got.Code == code || got.Code.Tries[0] == code.Tries[0] || got.Code.Handlers[0] == code.Handlers[0] {
		t.Fatal("exception metadata was not deeply copied")
	}

	code.Insns[0] = 0
	handler.TypeName = "Lmutated;"
	method.Parameters[0] = "Lmutated;"
	parser.strings[0] = "mutated"
	parser.methods[0].MethodName = "mutated"

	if got.CodeUnits[0] != 0x001a {
		t.Fatalf("owned code mutated with parser storage: %#x", got.CodeUnits[0])
	}
	if got.Code.Handlers[0].TypeName != "Ljava/lang/Exception;" {
		t.Fatalf("owned handler mutated: %q", got.Code.Handlers[0].TypeName)
	}
	if got.Parameters[0] != "Ljava/lang/String;" {
		t.Fatalf("owned parameters mutated: %q", got.Parameters[0])
	}
	if got.References.Strings[0] != "ciphertext" || got.References.Methods[0].MethodName != "decode" {
		t.Fatal("owned reference snapshot mutated with parser tables")
	}
}

func TestWalkClassOwnedProgressSkipsMethodLiftWhenHyperionDisabled(t *testing.T) {
	code := &CodeItem{Insns: []uint16{
		0x001a, 0x0000,
		0x1071, 0x0000, 0x0000,
		0x000e,
	}}
	method := &EncodedMethod{Name: "a", ClassName: "Lx/A;", Code: code}
	parser := &DEXParser{lazyCode: true, classes: []*ClassDef{{ClassName: "Lx/A;", DirectMethods: []*EncodedMethod{method}}}}
	var got DEXClassIR
	if err := parser.WalkClassOwnedProgress(context.Background(), OwnedDEXOptions{}, func(unit DEXClassIR) error {
		got = unit
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(got.Methods) != 0 {
		t.Fatalf("disabled Hyperion lifted %d methods", len(got.Methods))
	}
	if method.Code != nil {
		t.Fatal("lazy code was retained after disabled-Hyperion visit")
	}
}

func TestWalkClassOwnedProgressHonorsCancelledContext(t *testing.T) {
	parser := &DEXParser{classes: []*ClassDef{{ClassName: "Lx/A;"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	visits := 0
	err := parser.WalkClassOwnedProgress(ctx, OwnedDEXOptions{}, func(DEXClassIR) error {
		visits++
		return nil
	}, nil)
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if visits != 0 {
		t.Fatalf("visitor called %d times after cancellation", visits)
	}
}

func TestProcessOwnedMethodReportsMeasuredProofs(t *testing.T) {
	codeUnits := []uint16{
		0x0012,         // const/4 v0, 0
		0x1112,         // const/4 v1, 1
		0x0290, 0x0100, // add-int v2, v0, v1
		0x000f, // return v0
	}
	owned := OwnedDEXMethod{
		ClassName: "Lx/A;", MethodName: "calc", CandidateScore: 2,
		CandidateReasons: []string{"constant-branch"},
		CodeUnits:        codeUnits, RawInsns: DecodeMethodIR(codeUnits, nil),
		Code: &CodeItem{RegistersSize: 3, InsnsSize: uint32(len(codeUnits))},
	}
	cfg := DefaultPipelineConfig()
	cfg.EnableDeadCodeElimination = false
	cfg.EnableOpaquePredicateRemoval = false
	cfg.EnablePatternSimplification = false
	cfg.EnableVariableRecovery = false
	result, err := NewDeobfuscationPipeline(cfg).ProcessOwnedMethod(context.Background(), owned)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Transformed || result.Metrics.ProofsAccepted == 0 {
		t.Fatalf("missing measured transform: %+v", result)
	}
	if result.Metrics.BlocksBefore <= 0 || result.Metrics.BlocksAfter <= 0 {
		t.Fatalf("missing CFG snapshots: %+v", result.Metrics)
	}
	for _, entry := range result.Journal {
		if entry.ClassName != owned.ClassName || entry.MethodName != owned.MethodName || entry.Proof == "" {
			t.Fatalf("invalid journal identity/proof: %+v", entry)
		}
	}
}

func TestProcessOwnedMethodHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewDeobfuscationPipeline(nil).ProcessOwnedMethod(ctx, OwnedDEXMethod{})
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestScoreHyperionCandidateRejectsOrdinaryMethod(t *testing.T) {
	raw := DecodeMethodIR([]uint16{0x0012, 0x000f}, nil) // const/4 v0, 0; return v0
	score, reasons := scoreHyperionCandidate(raw)
	if score != 0 || len(reasons) != 0 {
		t.Fatalf("ordinary method score=%d reasons=%v, want zero", score, reasons)
	}
}
