package pipeline

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

// The deobfuscation stage was, for its whole life, a no-op on real scans: it
// filtered its input on types.FileAnalysis.CFG, a field nothing in the tree
// ever assigns, and on types.FileTypeSmali, which DEX-lifted classes are not
// labelled with. Both filters passed every unit test in the package because
// every unit test called the engine directly rather than the stage.
//
// These tests exercise the stage. They fail if the stage stops reaching
// methods, and they fail if recovered plaintext stops reaching the match set.

// newDeobfTestPipeline builds a real Pipeline so the stage runs against the
// same matcher and config production uses.
func newDeobfTestPipeline(t *testing.T) *Pipeline {
	t.Helper()
	p, err := NewPipeline(config.DefaultConfig())
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return p
}

// smaliClassWithEncryptedURL builds a parsed class whose single method hides an
// endpoint behind a base64 literal passed to a decryptor.
func smaliClassWithEncryptedURL(t *testing.T, className, hidden string) *types.FileAnalysis {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(hidden))
	body := []string{
		"    .registers 4",
		`    const-string v0, "` + encoded + `"`,
		"    const/4 v1, 0x3",
		"    invoke-static {v0, v1}, Lcom/x/D;->a(Ljava/lang/String;I)Ljava/lang/String;",
		"    move-result-object v2",
		"    return-object v2",
	}
	return &types.FileAnalysis{
		Path: "smali/com/example/Hidden.smali",
		Type: types.FileTypeDex, // as a class lifted from classes.dex is labelled
		SmaliClass: &types.SmaliClass{
			Name: className,
			Methods: []types.SmaliMethod{{
				Name:       "endpoint",
				Params:     "()",
				ReturnType: "Ljava/lang/String;",
				Body:       body,
			}},
		},
	}
}

func TestDeobfuscationStageReachesDexLiftedClasses(t *testing.T) {
	const hidden = "https://c2.example.net/collect"

	p := newDeobfTestPipeline(t)
	fa := smaliClassWithEncryptedURL(t, "Lcom/example/Hidden;", hidden)
	p.result = &types.AnalysisResult{
		Files: map[string]*types.FileAnalysis{fa.Path: fa},
	}

	p.deobfuscateClass(fa, fa.SmaliClass)
	p.runDeobfuscation()

	if p.result.Deobfuscation == nil {
		t.Fatal("result.Deobfuscation is nil: the stage never published its findings")
	}
	if p.result.Deobfuscation.RecoveredStrings == 0 {
		t.Fatal("stage recovered nothing from a DEX-lifted class; the input filter is dropping methods again")
	}
	if len(fa.RecoveredStrings) == 0 {
		t.Fatal("no plaintext attached to the file")
	}
	found := false
	for _, s := range fa.RecoveredStrings {
		if s == hidden {
			found = true
		}
	}
	if !found {
		t.Errorf("recovered %q, want %q among them", fa.RecoveredStrings, hidden)
	}
	if len(fa.MethodCFGs) != len(fa.SmaliClass.Methods) || fa.MethodCFGs[0] == nil {
		t.Fatalf("deobfuscation did not retain the per-method CFG cache: %#v", fa.MethodCFGs)
	}
}

// TestRecoveredStringsReachTheMatchSet is the point of the whole stage.
// Decrypted text used to be written to a field no reader consumed, so a
// recovered credential or C2 endpoint never met a single rule.
func TestRecoveredStringsReachTheMatchSet(t *testing.T) {
	const hidden = "https://c2.example.net/collect"

	p := newDeobfTestPipeline(t)
	fa := smaliClassWithEncryptedURL(t, "Lcom/example/Hidden;", hidden)
	before := len(fa.Matches)
	p.result = &types.AnalysisResult{
		Files: map[string]*types.FileAnalysis{fa.Path: fa},
	}

	p.deobfuscateClass(fa, fa.SmaliClass)
	p.rescanRecoveredContent(context.Background(), fa, FileJob{
		Path: fa.Path, RelPath: fa.Path, Type: types.FileTypeSmali,
	})

	if len(fa.Matches) <= before {
		t.Fatalf("decrypted text produced no new matches (%d before, %d after): "+
			"deobfuscation output is not being fed back into scanning", before, len(fa.Matches))
	}
	sawDecryptedProvenance := false
	for _, m := range fa.Matches {
		if m.ResolvedContext == "decrypted string" {
			sawDecryptedProvenance = true
			break
		}
	}
	if !sawDecryptedProvenance {
		t.Error("no match carries decrypted-string provenance; a reviewer cannot tell it from a cleartext hit")
	}
}

// TestRecoveredStringsEnterRuleContext checks the other consumer: the rule
// engine builds its evidence from a per-file context, and recovered plaintext
// has to appear in it.
func TestRecoveredStringsEnterRuleContext(t *testing.T) {
	const hidden = "https://c2.example.net/collect"

	fa := &types.FileAnalysis{
		Path:             "smali/com/example/Hidden.smali",
		Type:             types.FileTypeDex,
		SmaliClass:       &types.SmaliClass{Name: "Lcom/example/Hidden;"},
		RecoveredStrings: []string{hidden},
	}

	ctx := buildFileContext(fa, nil)
	if ctx == nil {
		t.Fatal("buildFileContext returned nil for a file carrying recovered strings")
	}
	for _, s := range ctx.Strings {
		if strings.Contains(s, "c2.example.net") {
			return
		}
	}
	t.Errorf("recovered plaintext missing from rule string corpus: %v", ctx.Strings)
}

// TestDeobfuscationIgnoresOrdinaryCode is the precision half: a class with no
// encrypted literals must yield no recoveries and no extra matches.
func TestApplyHyperionMethodsPublishesMeasuredFacts(t *testing.T) {
	p := newDeobfTestPipeline(t)
	fa := &types.FileAnalysis{Path: "classes.dex!/Lx/A;", Type: types.FileTypeDex}
	codeUnits := []uint16{
		0x0012,         // const/4 v0, 0
		0x1112,         // const/4 v1, 1
		0x0290, 0x0100, // add-int v2, v0, v1
		0x000f, // return v0
	}
	owned := []apkloader.OwnedDEXMethod{{
		ClassName: "Lx/A;", MethodName: "calc", CandidateScore: 2,
		CandidateReasons: []string{"constant-branch"},
		RawInsns:         apkloader.DecodeMethodIR(codeUnits, nil),
		Code:             &apkloader.CodeItem{RegistersSize: 3, InsnsSize: uint32(len(codeUnits))},
	}}
	cfg := apkloader.DefaultPipelineConfig()
	cfg.EnableDeadCodeElimination = false
	cfg.EnableOpaquePredicateRemoval = false
	cfg.EnablePatternSimplification = false
	cfg.EnableVariableRecovery = false
	p.applyHyperionMethods(context.Background(), fa, apkloader.NewDeobfuscationPipeline(cfg), owned)
	if fa.Deobfuscation == nil || fa.Deobfuscation.MethodsConsidered != 1 {
		t.Fatalf("missing Hyperion candidate accounting: %+v", fa.Deobfuscation)
	}
	if fa.Deobfuscation.MethodsTransformed != 1 || fa.Deobfuscation.ProofsAccepted == 0 {
		t.Fatalf("missing material transform facts: %+v", fa.Deobfuscation)
	}
	if len(fa.Deobfuscation.Methods) != 1 || fa.Deobfuscation.Methods[0].Metrics == nil {
		t.Fatalf("missing per-method metrics: %+v", fa.Deobfuscation.Methods)
	}
	m := fa.Deobfuscation.Methods[0]
	if m.Metrics.BlocksBefore <= 0 || len(m.Journal) == 0 || m.Journal[0].Proof == "" {
		t.Fatalf("invalid measured provenance: %+v", m)
	}
}

func TestApplyHyperionMethodsPublishesEmulatorRecovery(t *testing.T) {
	p := newDeobfTestPipeline(t)
	fa := &types.FileAnalysis{Path: "classes.dex!/Lx/D;", Type: types.FileTypeDex}
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
	method := apkloader.OwnedDEXMethod{
		ClassName: "Lx/D;", MethodName: "decrypt", CandidateScore: 3,
		RegistersSize: 4, CodeUnits: code, RawInsns: apkloader.DecodeMethodIR(code, nil),
		Code: &apkloader.CodeItem{RegistersSize: 4, InsnsSize: uint32(len(code))},
		References: apkloader.DEXReferenceSnapshot{
			Strings: map[uint32]string{0: "https://c2.example/collect"},
			Types:   map[uint32]string{0: "Ljava/lang/StringBuilder;"},
			Methods: map[uint32]apkloader.Method{
				0: {ClassName: "Ljava/lang/StringBuilder;", MethodName: "<init>", ReturnType: "V"},
				1: {ClassName: "Ljava/lang/StringBuilder;", MethodName: "append", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/StringBuilder;"},
				2: {ClassName: "Ljava/lang/StringBuilder;", MethodName: "toString", ReturnType: "Ljava/lang/String;"},
			},
			Fields: map[uint32]apkloader.Field{},
		},
		InvokeArgs: map[uint32][]uint16{2: {0}, 7: {0, 1}, 11: {2}},
	}
	cfg := apkloader.DefaultPipelineConfig()
	cfg.EnableConstantPropagation = false
	cfg.EnableDeadCodeElimination = false
	cfg.EnableOpaquePredicateRemoval = false
	cfg.EnablePatternSimplification = false
	p.applyHyperionMethods(context.Background(), fa, apkloader.NewDeobfuscationPipeline(cfg), []apkloader.OwnedDEXMethod{method})
	if len(fa.RecoveredStrings) != 1 || fa.RecoveredStrings[0] != "https://c2.example/collect" {
		t.Fatalf("emulator plaintext missing: %+v", fa)
	}
	if fa.Deobfuscation.EmulatorRecoveries != 1 || len(fa.Deobfuscation.Methods[0].RecoveredValues) != 1 {
		t.Fatalf("emulator provenance missing: %+v", fa.Deobfuscation)
	}
	if fa.Deobfuscation.Methods[0].Transformed {
		t.Fatal("emulator recovery was mislabeled as structural transformation")
	}
}

func TestApplyHyperionMethodsPublishesStaticSnapshotRecovery(t *testing.T) {
	p := newDeobfTestPipeline(t)
	fa := &types.FileAnalysis{Path: "classes.dex!/Lx/D;", Type: types.FileTypeDex}
	code := []uint16{
		0x0062, 0x0000, // sget-object v0, field@0
		0x011a, 0x0000, // const-string v1, string@0
		0x206e, 0x0000, 0x0010, // concat {v0,v1}
		0x020c,
		0x0211,
	}
	method := apkloader.OwnedDEXMethod{
		ClassName: "Lx/D;", MethodName: "endpoint", ReturnType: "Ljava/lang/String;", CandidateScore: 3,
		RegistersSize: 3, CodeUnits: code, RawInsns: apkloader.DecodeMethodIR(code, nil),
		Code: &apkloader.CodeItem{RegistersSize: 3, InsnsSize: uint32(len(code))},
		References: apkloader.DEXReferenceSnapshot{
			Strings: map[uint32]string{0: "c2.example"},
			Fields:  map[uint32]apkloader.Field{0: {ClassName: "Lx/K;", FieldName: "PREFIX", TypeName: "Ljava/lang/String;"}},
			Methods: map[uint32]apkloader.Method{0: {ClassName: "Ljava/lang/String;", MethodName: "concat", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/String;"}},
			Types:   map[uint32]string{},
		},
		InvokeArgs: map[uint32][]uint16{4: {0, 1}},
	}
	statics := apkloader.NewOwnedStaticResolver(map[string]apkloader.OwnedStaticValue{
		"Lx/K;->PREFIX:Ljava/lang/String;": {Kind: apkloader.StaticString, TypeName: "Ljava/lang/String;", String: "https://", Operations: []string{"dex-encoded-value"}},
	})
	cfg := apkloader.DefaultPipelineConfig()
	cfg.EnableConstantPropagation = false
	cfg.EnableDeadCodeElimination = false
	cfg.EnableOpaquePredicateRemoval = false
	cfg.EnablePatternSimplification = false
	p.applyHyperionMethodsWithEnvironment(context.Background(), fa, apkloader.NewDeobfuscationPipeline(cfg), []apkloader.OwnedDEXMethod{method}, apkloader.NewOwnedMethodResolver(nil), statics)
	if len(fa.RecoveredStrings) != 1 || fa.RecoveredStrings[0] != "https://c2.example" {
		t.Fatalf("static snapshot plaintext missing: %+v", fa)
	}
	if fa.Deobfuscation.Methods[0].Transformed {
		t.Fatal("static recovery was mislabeled as structural transformation")
	}
}

func TestApplyHyperionMethodsHonorsCancellation(t *testing.T) {
	p := newDeobfTestPipeline(t)
	fa := &types.FileAnalysis{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.applyHyperionMethods(ctx, fa, apkloader.NewDeobfuscationPipeline(nil), []apkloader.OwnedDEXMethod{{MethodName: "m"}})
	if fa.Deobfuscation == nil || fa.Deobfuscation.MethodsConsidered != 0 {
		t.Fatalf("cancelled method was processed: %+v", fa.Deobfuscation)
	}
}

func TestDeobfuscationIgnoresOrdinaryCode(t *testing.T) {
	p := newDeobfTestPipeline(t)
	fa := &types.FileAnalysis{
		Path: "smali/androidx/core/IconCompat.smali",
		Type: types.FileTypeDex,
		SmaliClass: &types.SmaliClass{
			Name: "Landroidx/core/IconCompat;",
			Methods: []types.SmaliMethod{{
				Name:       "getType",
				Params:     "()",
				ReturnType: "I",
				Body: []string{
					"    .registers 2",
					`    const-string v0, "IconCompat"`,
					`    const-string v1, "TypefaceCompat"`,
					"    invoke-static {v0}, Landroid/util/Log;->d(Ljava/lang/String;)I",
					"    return v0",
				},
			}},
		},
	}
	p.result = &types.AnalysisResult{
		Files: map[string]*types.FileAnalysis{fa.Path: fa},
	}

	p.deobfuscateClass(fa, fa.SmaliClass)

	if len(fa.RecoveredStrings) != 0 {
		t.Errorf("ordinary identifiers were reported as decrypted: %q", fa.RecoveredStrings)
	}
}
