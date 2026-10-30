package ml

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const auditFixture = `.class public Lapp/Flow;
.super Ljava/lang/Object;
.method public static read(Landroid/content/Intent;)Ljava/lang/String;
 .locals 2
 const-string v1, "input"
 invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
 move-result-object v0
 return-object v0
.end method
.method public static consume(Landroid/content/Intent;)V
 .locals 3
 invoke-static {p0}, Lapp/Flow;->read(Landroid/content/Intent;)Ljava/lang/String;
 move-result-object v0
 invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
 move-result-object v1
 invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
 return-void
.end method
.method public static safe()V
 .locals 2
 const-string v0, "not-a-user-command"
 invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
 move-result-object v1
 invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
 return-void
.end method
`

func auditInput() []SmaliAuditFile {
	return []SmaliAuditFile{{Path: "smali/app/Flow.smali", Content: []byte(auditFixture)}}
}
func TestAuditChainBuildsEvidenceWithPhysicalLines(t *testing.T) {
	r := NewSmaliAuditChain(SmaliAuditConfig{AppPackage: "app"}).Analyze(context.Background(), auditInput())
	if !r.AnalysisComplete {
		t.Fatalf("incomplete: %v", r.Diagnostics)
	}
	if r.Coverage.MethodsAnalyzed != 3 || len(r.Stages) != 5 {
		t.Fatalf("coverage=%+v stages=%+v", r.Coverage, r.Stages)
	}
	count := 0
	for _, f := range r.Findings {
		if f.EvidenceLevel != "static_flow" {
			continue
		}
		count++
		if f.Category != "command_injection" || !strings.Contains(f.Location.Method, "consume(") {
			t.Fatalf("bad flow: %+v", f)
		}
		if f.Location.Line != 16 {
			t.Errorf("sink line=%d", f.Location.Line)
		}
		if f.Origin != "app_package" || !f.ReviewRequired || f.Confidence > .85 {
			t.Errorf("wrong evidence contract: %+v", f)
		}
		if len(f.Evidence) < 2 || f.Evidence[0].Line != 6 {
			t.Errorf("wrong source evidence: %+v", f.Evidence)
		}
		for _, e := range f.Evidence {
			if e.File == "" {
				t.Error("missing evidence file")
			}
		}
	}
	if count != 1 {
		t.Fatalf("flows=%d", count)
	}
	if r.Stages[1].Name != "method_signals" || r.Stages[1].InputCount != 3 {
		t.Fatal("pipeline was not executed")
	}
}
func TestAuditChainDeterministicAcrossWorkersAndOrder(t *testing.T) {
	a := auditInput()[0]
	b := SmaliAuditFile{Path: "Empty.smali", Content: []byte(".class public Lapp/Empty;\n.super Ljava/lang/Object;\n")}
	left := NewSmaliAuditChain(SmaliAuditConfig{Workers: 1}).Analyze(context.Background(), []SmaliAuditFile{b, a})
	right := NewSmaliAuditChain(SmaliAuditConfig{Workers: 8}).Analyze(context.Background(), []SmaliAuditFile{a, b})
	if !reflect.DeepEqual(left.Findings, right.Findings) || !reflect.DeepEqual(left.Coverage, right.Coverage) {
		t.Fatal("results depend on input order or workers")
	}
}
func TestAuditChainRetainsLibraryFlows(t *testing.T) {
	files := []SmaliAuditFile{{Path: "smali/com/google/firebase/Flow.smali", Content: []byte(strings.ReplaceAll(auditFixture, "Lapp/Flow;", "Lcom/google/firebase/Flow;"))}}
	r := NewSmaliAuditChain(SmaliAuditConfig{}).Analyze(context.Background(), files)
	for _, f := range r.Findings {
		if f.EvidenceLevel == "static_flow" {
			if f.Origin != "known_library" {
				t.Fatalf("origin=%s", f.Origin)
			}
			return
		}
	}
	t.Fatal("library flow suppressed")
}
func TestAuditChainReportsIncompleteInput(t *testing.T) {
	tests := []struct {
		name   string
		config SmaliAuditConfig
		files  []SmaliAuditFile
	}{
		{"empty", SmaliAuditConfig{}, nil},
		{"broken", SmaliAuditConfig{}, []SmaliAuditFile{{Path: "bad.smali", Content: []byte(".class Lapp/Bad;\n.method a()V\n")}}},
		{"file_bytes", SmaliAuditConfig{MaxFileBytes: 1}, auditInput()},
		{"total_bytes", SmaliAuditConfig{MaxTotalBytes: 1}, auditInput()},
		{"methods", SmaliAuditConfig{MaxMethods: 1}, auditInput()},
		{"findings", SmaliAuditConfig{MaxFindings: 1}, auditInput()},
		{"duplicates", SmaliAuditConfig{}, []SmaliAuditFile{{Path: "A.smali", Content: []byte(auditFixture)}, {Path: "B.smali", Content: []byte(auditFixture)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewSmaliAuditChain(tc.config).Analyze(context.Background(), tc.files)
			if r.AnalysisComplete || len(r.Diagnostics) == 0 || r.Verdict != "incomplete_review_required" {
				t.Fatalf("silent incomplete scan: %+v", r)
			}
		})
	}
}
func TestAuditChainCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := NewSmaliAuditChain(SmaliAuditConfig{}).Analyze(ctx, auditInput())
	if r.AnalysisComplete {
		t.Fatal("cancelled audit claims completeness")
	}
}
func TestAuditChainRedactsLiterals(t *testing.T) {
	r := NewSmaliAuditChain(SmaliAuditConfig{}).Analyze(context.Background(), auditInput())
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "not-a-user-command") {
		t.Fatal("raw literal leaked")
	}
	if !strings.Contains(string(data), "literal redacted") {
		t.Fatal("missing redacted evidence")
	}
}
func TestAuditChainFlowOnly(t *testing.T) {
	r := NewSmaliAuditChain(SmaliAuditConfig{NoHeuristics: true}).Analyze(context.Background(), auditInput())
	if len(r.Findings) != 1 || r.Findings[0].EvidenceLevel != "static_flow" {
		t.Fatal("flow-only ignored")
	}
}
func TestAuditChainConcurrentInvocations(t *testing.T) {
	chain := NewSmaliAuditChain(SmaliAuditConfig{Workers: 2})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := chain.Analyze(context.Background(), auditInput())
			if r.Coverage.StaticFlows != 1 {
				t.Error("concurrent run lost flow")
			}
		}()
	}
	wg.Wait()
}
func TestAuditPipelineMapErrorsDoNotMutateInput(t *testing.T) {
	input := make([]ScoredMethod, 64)
	input[0].Method.Name = "path_error"
	stage := ParallelMapStageContext("mixed_errors", 8, func(_ context.Context, sm *ScoredMethod) error {
		sm.Score.FinalScore = 123
		if sm.Method.Name == "path_error" {
			return &os.PathError{Op: "test", Path: "fixture", Err: errors.New("fixture")}
		}
		return errors.New("fixture error")
	})
	if _, err := stage.Process(context.Background(), input); err == nil {
		t.Fatal("expected error")
	}
	for _, sm := range input {
		if sm.Score.FinalScore != 0 {
			t.Fatal("failed mapper changed input")
		}
	}
}
func TestAuditPipelineBudgetAndFreshMetrics(t *testing.T) {
	p := NewMLPipeline(1, NewStage("deadline", time.Millisecond, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) { <-ctx.Done(); return in, nil }))
	_, m := p.Run(context.Background(), []ScoredMethod{{}})
	if len(m.Errors) != 1 || m.Stages[0].Error == "" {
		t.Fatal("deadline ignored")
	}
	p = NewMLPipeline(1, FilterStage("filter", func(*ScoredMethod) bool { return false }))
	p.Run(context.Background(), []ScoredMethod{{}})
	_, m = p.Run(context.Background(), nil)
	if m.TotalMethods != 0 || m.Throughput != 0 {
		t.Fatalf("stale metrics: %+v", m)
	}
}
func TestAuditScoreStageActuallyScores(t *testing.T) {
	pa := NewPatchAnalyzer()
	ci := pa.AnalyzeSmaliContent("License.smali", []byte(smaliLicenseCheck))
	out, err := ScoreStage(nil, pa).Process(context.Background(), []ScoredMethod{{Method: ci.Methods[0]}})
	if err != nil || len(out) != 1 || out[0].Score.FinalScore == 0 {
		t.Fatalf("score stage is a no-op: %v %+v", err, out)
	}
}
func TestAuditSmaliStringLexing(t *testing.T) {
	cases := map[string]string{
		`const-string v0, "hello#world" # "ignored"`: "hello#world",
		`const-string v0, "say \"yes\"" # "ignored"`: "say \"yes\"",
		`const-string v0, "\u0041\ud83d\ude00"`:      "A😀",
		`const-string v0, "broken`:                   "",
	}
	for line, want := range cases {
		if got := extractConstString(line); got != want {
			t.Errorf("%q -> %q want %q", line, got, want)
		}
	}
}
func FuzzAuditSmaliParserNoPanic(f *testing.F) {
	f.Add(auditFixture)
	f.Add(".class Lapp/A;\n.method a()V\n.end method\n")
	f.Add("\x00\xff# malformed")
	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > 32768 {
			t.Skip()
		}
		pa := NewPatchAnalyzer()
		ci := pa.AnalyzeSmaliContent("fuzz.smali", []byte(content))
		if ci == nil {
			t.Fatal("nil class")
		}
		PutClassInfo(ci)
	})
}

func TestAuditSmaliAcceptsTabsBetweenTokens(t *testing.T) {
	content := strings.ReplaceAll(auditFixture, " ", "\t")
	r := NewSmaliAuditChain(SmaliAuditConfig{}).Analyze(context.Background(), []SmaliAuditFile{{Path: "Tabs.smali", Content: []byte(content)}})
	if !r.AnalysisComplete || r.Coverage.MethodsAnalyzed != 3 || r.Coverage.StaticFlows != 1 {
		t.Fatalf("tabs break smali parsing: coverage=%+v diagnostics=%+v", r.Coverage, r.Diagnostics)
	}
}

func TestAuditMobileURLFlowDoesNotClaimServerSideRequestForgery(t *testing.T) {
	content := `.class public Lapp/URLFlow;
.super Ljava/lang/Object;
.method public static build(Landroid/content/Intent;)V
 .locals 3
 invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
 move-result-object v0
 new-instance v1, Ljava/net/URL;
 invoke-direct {v1, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
 return-void
.end method
`
	r := NewSmaliAuditChain(SmaliAuditConfig{NoHeuristics: true}).Analyze(context.Background(), []SmaliAuditFile{{Path: "URL.smali", Content: []byte(content)}})
	if len(r.Findings) != 1 || r.Findings[0].Category != "untrusted_network_destination" {
		t.Fatalf("mobile URL flow mislabeled: %+v", r.Findings)
	}
}
