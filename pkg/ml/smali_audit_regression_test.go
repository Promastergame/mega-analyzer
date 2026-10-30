package ml

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestAuditParserRetainedMethodsOwnTheirSlices(t *testing.T) {
	pa := NewPatchAnalyzer()
	ci := pa.AnalyzeSmaliContent("Flow.smali", []byte(`.class public Lapp/Flow;
.super Ljava/lang/Object;
.method public static first()V
 .locals 1
 const-string v0, "first-value"
 invoke-static {v0}, Lapp/First;->accept(Ljava/lang/String;)V
 return-void
.end method
.method public static second()V
 .locals 1
 const-string v0, "second-value"
 invoke-static {v0}, Lapp/Second;->accept(Ljava/lang/String;)V
 return-void
.end method
`))
	if len(ci.Methods) != 2 {
		t.Fatalf("methods=%d", len(ci.Methods))
	}
	for i, want := range []string{"first-value", "second-value"} {
		if !reflect.DeepEqual(ci.Methods[i].StringConsts, []string{want}) {
			t.Errorf("method %d strings=%q, want %q", i, ci.Methods[i].StringConsts, want)
		}
	}
	if got := ci.Methods[0].Calls[0].Class; got != "app/First" {
		t.Errorf("first method call corrupted: %s", got)
	}
	// A later file must not mutate results already handed to a caller.
	pa.AnalyzeSmaliContent("Later.smali", []byte(`.class public Lapp/Later;
.super Ljava/lang/Object;
.method public static later()V
 const-string v0, "later-value"
 invoke-static {v0}, Lapp/Later;->accept(Ljava/lang/String;)V
 return-void
.end method`))
	if got := ci.Methods[0].StringConsts[0]; got != "first-value" {
		t.Errorf("later parse changed first result: %q", got)
	}
}

func TestAuditParserClassNameContainingCapitalL(t *testing.T) {
	pa := NewPatchAnalyzer()
	call := pa.parseInvoke("invoke-virtual {v0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;")
	if call == nil || call.Class != "java/lang/ClassLoader" {
		t.Fatalf("wrong invoke owner: %+v", call)
	}
}

func TestAuditParserCountsOnlyInstructions(t *testing.T) {
	ci := NewPatchAnalyzer().AnalyzeSmaliContent("A.smali", []byte(`.class public Lapp/A;
.super Ljava/lang/Object;
.method public static a()V
 .locals 1
 .annotation runtime Lapp/Metadata;
  value = "not executable"
 .end annotation
 const-string v0, "hello#world" # a real comment
 return-void
.end method`))
	if len(ci.Methods) != 1 {
		t.Fatal("missing method")
	}
	if n := ci.Methods[0].InstructionCount; n != 2 {
		t.Errorf("instructions=%d, want 2", n)
	}
}

func TestAuditPoolResetsLanguageAndClassPath(t *testing.T) {
	mi := GetMethodInfo()
	mi.SourceLanguage = LanguageKotlin
	mi.ClassPath = "Lapp/Old;"
	PutMethodInfo(mi)
	if mi.ClassPath != "" || mi.SourceLanguage != "" {
		t.Fatalf("stale fields in pool: %q %q", mi.ClassPath, mi.SourceLanguage)
	}
}

func TestAuditPipelineMetricsSnapshotsAreIsolated(t *testing.T) {
	p := NewMLPipeline(2, NewStage("pass", 0, func(_ context.Context, in []ScoredMethod) ([]ScoredMethod, error) { return in, nil }))
	_, metrics := p.Run(context.Background(), []ScoredMethod{{}})
	metrics.Stages[0].Name = "corrupted"
	if p.Metrics().Stages[0].Name != "pass" {
		t.Fatal("Run returned aliased metrics")
	}
}

func TestAuditPipelineFailedStageDoesNotClaimFiltering(t *testing.T) {
	p := NewMLPipeline(1, NewStage("failure", 0, func(_ context.Context, _ []ScoredMethod) ([]ScoredMethod, error) { return nil, fmt.Errorf("expected") }))
	out, m := p.Run(context.Background(), make([]ScoredMethod, 3))
	if len(out) != 3 || m.Stages[0].Filtered != 0 {
		t.Fatalf("fail-open accounting: len=%d metrics=%+v", len(out), m.Stages)
	}
}

func TestAuditPipelineConcurrentRunAndMetrics(t *testing.T) {
	p := NewMLPipeline(1, NewStage("pass", 0, func(_ context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		time.Sleep(time.Microsecond)
		return in, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				p.Run(context.Background(), []ScoredMethod{{}})
				_ = p.Metrics()
			}
		}()
	}
	wg.Wait()
}
