package apkloader

// RAM-budget regression tests: streaming DEX ownership, bounded native
// payload cache and capped pretty-Smali retention.
//
// Background: a paranoid scan of a 6k-class DEX used to retain every class IR
// at once (100-200 MiB), pin every .so in nativeData, and accumulate pretty
// Smali without a ceiling. These tests pin the bounded behavior.

import (
	"context"
	"path/filepath"
	"testing"
)

// streamParityParser builds a synthetic parser with three classes: two with
// obfuscation-like candidate methods and one empty. IR generation works on it
// (same shape as dex_ir_owned_test fixtures).
func streamParityParser(lazy bool) *DEXParser {
	mkCode := func() *CodeItem {
		return &CodeItem{
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
		}
	}
	mkMethod := func(class, name string) *EncodedMethod {
		return &EncodedMethod{
			MethodIdx:   0,
			Name:        name,
			ClassName:   class,
			ReturnType:  "Ljava/lang/String;",
			Parameters:  []string{"Ljava/lang/String;"},
			AccessFlags: 0x0008,
			Code:        mkCode(),
		}
	}
	return &DEXParser{
		lazyCode: lazy,
		strings:  []string{"ciphertext"},
		methods: []*Method{{
			ClassName:  "Lx/A;",
			MethodName: "decode",
			ReturnType: "Ljava/lang/String;",
			Parameters: []string{"Ljava/lang/String;"},
		}},
		classes: []*ClassDef{
			{ClassName: "Lx/A;", DirectMethods: []*EncodedMethod{mkMethod("Lx/A;", "a")}},
			{ClassName: "Lx/B;", DirectMethods: []*EncodedMethod{mkMethod("Lx/B;", "b")}},
			{ClassName: "Lx/Empty;"},
		},
	}
}

func collectStreamed(t *testing.T, parser *DEXParser, options OwnedDEXOptions) ([]DEXClassIR, *OwnedEnvironment) {
	t.Helper()
	var classes []DEXClassIR
	var gotEnv *OwnedEnvironment
	err := parser.StreamOwnedBundle(context.Background(), options, func(class DEXClassIR, env *OwnedEnvironment) error {
		classes = append(classes, class)
		gotEnv = env
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("StreamOwnedBundle failed: %v", err)
	}
	return classes, gotEnv
}

// TestStreamCollectParity: streaming must emit exactly what the collector
// returns — same classes in the same order, byte-identical IR, same lifted
// candidates — without retaining them all at once.
func TestStreamCollectParity(t *testing.T) {
	options := OwnedDEXOptions{EnableHyperion: true, MinCandidateScore: 2}

	bundle, err := streamParityParser(false).CollectOwnedBundle(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("CollectOwnedBundle failed: %v", err)
	}
	streamed, env := collectStreamed(t, streamParityParser(false), options)

	if env == nil || env.Resolver == nil {
		t.Fatal("streamed environment or resolver is nil")
	}
	if len(streamed) != len(bundle.Classes) {
		t.Fatalf("streamed %d classes, collected %d", len(streamed), len(bundle.Classes))
	}
	for i := range streamed {
		if streamed[i].ClassName != bundle.Classes[i].ClassName {
			t.Fatalf("class %d: streamed %q, collected %q", i, streamed[i].ClassName, bundle.Classes[i].ClassName)
		}
		if string(streamed[i].IR) != string(bundle.Classes[i].IR) {
			t.Fatalf("class %s: IR mismatch", streamed[i].ClassName)
		}
		if len(streamed[i].Methods) != len(bundle.Classes[i].Methods) {
			t.Fatalf("class %s: streamed %d methods, collected %d",
				streamed[i].ClassName, len(streamed[i].Methods), len(bundle.Classes[i].Methods))
		}
	}
	if env.Resolver.Len() != bundle.Resolver.Len() {
		t.Fatalf("streamed resolver holds %d methods, collected %d", env.Resolver.Len(), bundle.Resolver.Len())
	}
}

// TestStreamReleasesParserCode: with a lazy parser the stream must not retain
// method code after emission, and the environment must still resolve the
// candidate lifted before release.
func TestStreamReleasesParserCode(t *testing.T) {
	parser := streamParityParser(true)
	streamed, env := collectStreamed(t, parser, OwnedDEXOptions{EnableHyperion: true, MinCandidateScore: 2})
	if len(streamed) != 3 {
		t.Fatalf("streamed %d classes, want 3", len(streamed))
	}
	for _, class := range parser.GetClasses() {
		for _, m := range append(append([]*EncodedMethod(nil), class.DirectMethods...), class.VirtualMethods...) {
			if m != nil && m.Code != nil {
				t.Fatalf("parser retained code for %s after stream", m.Descriptor())
			}
		}
	}
	if env.Resolver == nil || env.Resolver.Len() == 0 {
		t.Fatal("environment resolver lost the pre-release candidates")
	}
}

// TestStreamHonorsCancellation: no class may be emitted after cancel.
func TestStreamHonorsCancellation(t *testing.T) {
	parser := streamParityParser(false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	visits := 0
	err := parser.StreamOwnedBundle(ctx, OwnedDEXOptions{}, func(DEXClassIR, *OwnedEnvironment) error {
		visits++
		return nil
	}, nil)
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if visits != 0 {
		t.Fatalf("emitted %d classes after cancellation", visits)
	}
}

// TestSmaliBudgetDropsDumpsKeepsCounters: dumps beyond the budget are dropped
// and counted; everything under the budget is retained byte-identical.
func TestSmaliBudgetDropsDumpsKeepsCounters(t *testing.T) {
	result := newPipelineResult()
	result.SmaliBudgetBytes = 16
	result.appendDeobfuscatedSmali("Lx/A;", "0123456789ABCDEF") // exactly 16 bytes: fits
	result.appendDeobfuscatedSmali("Lx/B;", "0123456789ABCDEF") // over budget: dropped
	result.appendDeobfuscatedSmali("Lx/C;", "")                 // empty: ignored, not counted
	result.finalizeDeobfuscatedClasses()

	if got := result.DeobfuscatedClasses["Lx/A;"]; got != "0123456789ABCDEF" {
		t.Fatalf("retained dump = %q, want intact", got)
	}
	if _, ok := result.DeobfuscatedClasses["Lx/B;"]; ok {
		t.Fatal("over-budget dump was retained")
	}
	if result.DroppedSmaliClasses != 1 {
		t.Fatalf("DroppedSmaliClasses = %d, want 1", result.DroppedSmaliClasses)
	}
}

// TestNativeDataCacheBounded: analyzeNativeSo must not grow the retained-bytes
// map past maxCachedNativeFiles, and the weaponization pass must free it.
func TestNativeDataCacheBounded(t *testing.T) {
	files, err := filepath.Glob("../../../testkit/native_test_corpus/bin/*.elf")
	if err != nil || len(files) == 0 {
		t.Skip("testkit corpus not present")
	}
	e := NewExtractor()
	e.nativeData = make(map[string][]byte, maxCachedNativeFiles)
	for i := 0; i < maxCachedNativeFiles; i++ {
		e.nativeData[string(rune('a'+i))] = []byte{byte(i)}
	}
	// Map is exactly at the cap: a further scan must not grow it — the
	// weaponization pass re-reads the file (capped) instead.
	e.analyzeNativeSo(files[0])
	if len(e.nativeData) > maxCachedNativeFiles {
		t.Fatalf("nativeData holds %d entries, cap is %d", len(e.nativeData), maxCachedNativeFiles)
	}
	e.runWeaponization(t.TempDir())
	if e.nativeData != nil {
		t.Fatalf("nativeData not freed after weaponization: %d entries", len(e.nativeData))
	}
}
