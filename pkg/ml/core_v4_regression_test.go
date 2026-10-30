package ml

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

const coreV4Fixture = `.class public Lapp/test/Feature;
.super Ljava/lang/Object;
.method public checkEnvironment()Z
 .locals 2
 new-instance v0, Ljava/io/File;
 const-string v1, "/system/xbin/su"
 invoke-direct {v0,v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
 invoke-virtual {v0}, Ljava/io/File;->exists()Z
 move-result v0
 return v0
.end method
`

func coreV4Predictor() *PatchPredictor {
	c := DefaultPredictorConfig()
	c.EnableGateDetection = false
	c.EnableDecoyDetection = false
	c.EnableEnsembleBoost = false
	c.EnableVulnSignals = false
	c.EnableConfidenceCalibration = false
	c.MaxHighRisk = 1
	c.MaxMediumRisk = 1
	c.MaxLowRisk = 1
	c.MaxAuditFindings = 1
	p := NewPatchPredictorWithConfig(io.Discard, c)
	p.history = nil
	p.feedbackIntegrator = nil
	p.enableNoiseFilter = false
	p.enableInterestingScore = false
	p.semanticGateDetector = nil
	p.entryPointDetector = nil
	return p
}
func coreV4Scored(name string, score float64, ret string) ScoredMethod {
	op, constant, locals := "return", "const/4 v0, 0x0", "1"
	if strings.HasPrefix(ret, "L") || strings.HasPrefix(ret, "[") {
		op = "return-object"
	}
	if ret == "J" || ret == "D" {
		op = "return-wide"
		constant = "const-wide/16 v0, 0x0"
		locals = "2"
	}
	body := []string{".method public " + name + "()" + ret, ".locals " + locals, constant, op + " v0", ".end method"}
	if ret == "V" {
		body = []string{".method public " + name + "()V", ".locals 0", "return-void", ".end method"}
	}
	return ScoredMethod{ClassPath: "app/test/Feature.smali", ClassName: "Lapp/test/Feature;", Method: MethodInfo{Name: name, NameLower: strings.ToLower(name), ClassName: "Lapp/test/Feature;", FilePath: "app/test/Feature.smali", ClassPath: "app/test/Feature.smali", FullSignature: name + "()" + ret, MethodHeader: body[0], ReturnType: ret, ReturnsBoolean: ret == "Z", IsAppCode: true, InstructionCount: 2, RawBody: body}, Score: ScoreResult{FinalScore: score, Confidence: score / 100, RiskLevel: RiskLevelFromScore(score), SuggestedPatch: PatchReturnFalse, PatchCategory: PatchCategory("root_detection")}}
}
func TestCoreMLV4PipelineActuallyRuns(t *testing.T) {
	p := coreV4Predictor().PredictFromCandidates([]AnalysisCandidate{{FilePath: "app/test/Feature.smali", Content: []byte(coreV4Fixture), IsAppCode: true}})
	m := p.Stats.PipelineMetrics
	if m == nil || len(m.Stages) == 0 || m.TotalMethods != 1 {
		t.Fatalf("main predictor never ran ML stages: %+v", m)
	}
}
func TestCoreMLV4FinalTopKUsesAllCandidates(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "better_late"
		if reverse {
			name = "better_first"
		}
		t.Run(name, func(t *testing.T) {
			a, b := coreV4Scored("first", 75, "Z"), coreV4Scored("best", 99, "Z")
			in := []ScoredMethod{a, b}
			if reverse {
				in = []ScoredMethod{b, a}
			}
			p := coreV4Predictor().buildPrediction(in, &BatchAnalyzeResult{TotalMethods: 2, AnalyzedMethods: 2})
			if len(p.HighRisk) != 1 || p.HighRisk[0].MethodName != "best" {
				t.Fatalf("better candidate discarded before final ranking: %+v", p.HighRisk)
			}
		})
	}
}
func TestCoreMLV4DirectoryDedupKeepsBetterValue(t *testing.T) {
	a := PatchPoint{FilePath: "app/A.smali", MethodName: "f", MethodSignature: "f()Z", RiskScore: 40}
	b := a
	b.RiskScore = 95
	got := retainTopPatchPoints([]PatchPoint{a}, []PatchPoint{b}, 1, patchValueOrFallback)
	if len(got) != 1 || got[0].RiskScore != 95 {
		t.Fatalf("stale duplicate kept: %+v", got)
	}
}
func TestCoreMLV4TieOrderIsDeterministic(t *testing.T) {
	a := PatchPoint{FilePath: "app/A.smali", MethodName: "a", MethodSignature: "a()Z", RiskScore: 90}
	b := PatchPoint{FilePath: "app/B.smali", MethodName: "b", MethodSignature: "b()Z", RiskScore: 90}
	x := retainTopPatchPoints(nil, []PatchPoint{a, b}, 1, patchValueOrFallback)
	y := retainTopPatchPoints(nil, []PatchPoint{b, a}, 1, patchValueOrFallback)
	if x[0].FilePath != y[0].FilePath {
		t.Fatalf("ties depend on input order: %s vs %s", x[0].FilePath, y[0].FilePath)
	}
}
func TestCoreMLV4NoInventedModelQuality(t *testing.T) {
	pp := coreV4Predictor()
	p := pp.emptyPrediction()
	p.Stats.TotalMethodsFound = 100
	p.Stats.PatchPointsFound = 2
	p.Stats.FilteredMethods = 90
	p.Stats.AvgScore = 95
	pp.enrichMLHealth(p)
	h := p.Stats.MLHealth
	if h.ECE != 0 || h.Brier != 0 || h.WorstPSI != 0 || h.Throughput != 0 || h.DriftVerdict != "unavailable" {
		t.Fatalf("invented quality without labels/reference/timing: %+v", h)
	}
}
func TestCoreMLV4UnreadableCandidateIsPartial(t *testing.T) {
	p := coreV4Predictor().PredictFromCandidates([]AnalysisCandidate{{FilePath: "missing.smali", FullPath: filepath.Join(testTempDir(t), "missing.smali"), IsAppCode: true}})
	if !p.PartialResults || p.Stats.FileReadErrors != 1 {
		t.Fatalf("input disappeared silently: partial=%v stats=%+v", p.PartialResults, p.Stats)
	}
}
func TestCoreMLV4CandidateOwnershipReachesMethods(t *testing.T) {
	body := strings.ReplaceAll(coreV4Fixture, "Lapp/test/Feature;", "Lcom/google/Owned;")
	b := NewPatchAnalyzer().BatchAnalyze([]AnalysisCandidate{{FilePath: "com/google/Owned.smali", Content: []byte(body), IsAppCode: true}})
	if len(b.Classes) != 1 || len(b.Classes[0].Methods) != 1 {
		t.Fatal("invalid fixture")
	}
	m := b.Classes[0].Methods[0]
	if !m.IsAppCode || m.IsLibrary {
		t.Fatalf("class override not propagated: app=%v lib=%v", m.IsAppCode, m.IsLibrary)
	}
}
func TestCoreMLV4LibraryAuditIsNotAnAutomaticPatch(t *testing.T) {
	m := coreV4Scored("inspect", 90, "Z")
	m.Method.IsAppCode = false
	m.Method.IsLibrary = true
	m.Method.ClassName = "Lcom/google/example/Inspect;"
	m.Score.VulnerabilitySignals = &VulnerabilitySignals{Signals: []VulnSignal{{Kind: VulnKind("hardcoded_secret"), Severity: VulnSeverityMedium, Confidence: 0.8}}, HighestSeverity: VulnSeverityMedium}
	p := coreV4Predictor().buildPrediction([]ScoredMethod{m}, &BatchAnalyzeResult{TotalMethods: 1, AnalyzedMethods: 1})
	if len(p.AuditFindings) != 1 {
		t.Fatalf("audit lost at automatic-rewrite gate: %+v", p.Stats)
	}
	if len(p.HighRisk)+len(p.MediumRisk)+len(p.LowRisk)+len(p.LibraryFindings) != 0 || p.AuditFindings[0].RuntimeDecision == "auto_patch" {
		t.Fatal("library audit became automatic patch")
	}
}
func TestCoreMLV4PredictionChecksReturnContract(t *testing.T) {
	for _, ret := range []string{"Z", "Ljava/lang/String;", "J", "[B", "V"} {
		t.Run(ret, func(t *testing.T) {
			m := coreV4Scored("inspect", 99, ret)
			p := coreV4Predictor().scoredMethodToPoint(&m)
			if ret != "Z" && p.RuntimeDecision == "auto_patch" {
				t.Fatalf("boolean intent on %s advertised automatic; typed fallback does not prove semantics", ret)
			}
			if ret == "Z" && p.RuntimeDecision == "reject" {
				t.Fatal("compatible boolean control rejected")
			}
		})
	}
}
