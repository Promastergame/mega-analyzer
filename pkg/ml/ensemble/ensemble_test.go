package ensemble

import (
	"math"
	"testing"
)

// fakeMethod implements MethodView for tests.
type fakeMethod struct {
	name        string
	sig         string
	ret         string
	insn        int
	regs        int
	ifs         int
	rets        int
	calls       []string
	consts      []string
	body        []string
	app         bool
	library     bool
	callback    bool
	constructor bool
}

func (f *fakeMethod) GetName() string           { return f.name }
func (f *fakeMethod) GetFullSignature() string  { return f.sig }
func (f *fakeMethod) GetReturnType() string     { return f.ret }
func (f *fakeMethod) GetInstructionCount() int  { return f.insn }
func (f *fakeMethod) GetRegisterCount() int     { return f.regs }
func (f *fakeMethod) GetIfCheckCount() int      { return f.ifs }
func (f *fakeMethod) GetReturnCount() int       { return f.rets }
func (f *fakeMethod) GetCalls() []string        { return f.calls }
func (f *fakeMethod) GetStringConsts() []string { return f.consts }
func (f *fakeMethod) GetRawBody() []string      { return f.body }
func (f *fakeMethod) GetIsAppCode() bool        { return f.app }
func (f *fakeMethod) GetIsLibrary() bool        { return f.library }
func (f *fakeMethod) GetIsCallback() bool       { return f.callback }
func (f *fakeMethod) GetIsConstructor() bool    { return f.constructor }

func TestExtract_HighRiskMethod(t *testing.T) {
	m := &fakeMethod{
		name: "isLicensed",
		sig:  "Lcom/example/security/LicenseChecker;->isLicensed()Z",
		ret:  "Z",
		insn: 30,
		regs: 8,
		ifs:  4,
		rets: 2,
		calls: []string{
			"Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
			"Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		},
		consts: []string{"VGhpcyBpcyBhIHNlY3JldA=="},
		body: []string{
			"const/4 v0, 0x0",
			"invoke-virtual {p0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
			"move-result-object v1",
			"if-eqz v1, :cond_0",
			"invoke-static {v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		},
		app: true,
	}
	f := Extract(m)
	if f.TaintFlowScore <= 0 {
		t.Fatalf("expected non-zero taint flow score, got %f", f.TaintFlowScore)
	}
	// One `if-eqz` in the body, so McCabe complexity is 2: one decision point
	// plus one. The old expectation of >= 4 encoded a double count — the
	// caller's if-check tally was added on top of the same conditionals the
	// body scan already counts — which saturated the log-squashed feature about
	// twice as early as it should.
	if f.Cyclomatic != 2 {
		t.Fatalf("expected cyclomatic == 2 for a body with one branch, got %f", f.Cyclomatic)
	}
}

// TestCyclomaticCountsEachBranchOnce pins the fix directly: the caller-supplied
// if-check count must not inflate a complexity already derived from the body.
func TestCyclomaticCountsEachBranchOnce(t *testing.T) {
	body := []string{
		"const/4 v0, 0x0",
		"if-eqz v0, :cond_0",
		"if-nez v0, :cond_1",
		"return-void",
	}
	// Two conditionals -> 1 + 2 = 3, whatever the caller claims separately.
	for _, ifChecks := range []int{0, 2, 5} {
		if got := cyclomatic(body, ifChecks); got != 3 {
			t.Errorf("cyclomatic(body, ifChecks=%d) = %v, want 3", ifChecks, got)
		}
	}
}

func TestScorer_HighVsLow(t *testing.T) {
	high := &fakeMethod{
		name: "checkLicense",
		sig:  "Lcom/example/security/Anti;->checkLicense()Z",
		ret:  "Z",
		insn: 40,
		ifs:  5,
		rets: 2,
		calls: []string{
			"Landroid/content/Intent;->getStringExtra",
			"Ljava/lang/Runtime;->exec",
		},
		consts: []string{"VGhpcyBpcyBhIHNlY3JldA==", "https://example.com/k"},
		body: []string{
			"if-eqz v0, :cond_0",
			"if-ne v1, v2, :cond_1",
			"invoke-virtual {p0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
			"invoke-static {v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		},
		app: true,
	}
	low := &fakeMethod{
		name: "getString",
		sig:  "Lcom/example/util/Helper;->getString()Ljava/lang/String;",
		ret:  "Ljava/lang/String;",
		insn: 5,
		body: []string{"const-string v0, \"hello\"", "return-object v0"},
		app:  true,
	}
	scorer := NewScorer()
	hi := scorer.Score(high)
	lo := scorer.Score(low)
	if hi.Final <= lo.Final {
		t.Fatalf("expected high > low, got high=%f low=%f", hi.Final, lo.Final)
	}
	if hi.Confidence <= 0 {
		t.Fatalf("expected positive confidence on high method, got %f", hi.Confidence)
	}
}

func TestScorer_LibraryPenalty(t *testing.T) {
	m := &fakeMethod{
		name:    "process",
		sig:     "Lcom/google/firebase/Foo;->process()V",
		insn:    5,
		body:    []string{"return-void"},
		library: true,
	}
	scorer := NewScorer()
	s := scorer.Score(m)
	for _, c := range s.Contributions {
		if c.Signal == "library_penalty" {
			if c.Delta >= 0 {
				t.Fatalf("expected negative delta for library penalty, got %f", c.Delta)
			}
			return
		}
	}
	t.Fatal("library_penalty contribution missing")
}

func TestShannonEntropy_Bounds(t *testing.T) {
	if h := shannonEntropy(""); h != 0 {
		t.Fatalf("empty string should return 0, got %f", h)
	}
	if h := shannonEntropy("aaaa"); h != 0 {
		t.Fatalf("uniform input should return 0 entropy, got %f", h)
	}
	// Random-ish bytes should produce positive entropy.
	if h := shannonEntropy("abcdefgh"); h <= 0 {
		t.Fatalf("expected positive entropy, got %f", h)
	}
	// Bound check.
	junk := make([]byte, 256)
	for i := range junk {
		junk[i] = byte(i)
	}
	if h := shannonEntropy(string(junk)); h > 8.001 || h < 7.5 {
		t.Fatalf("expected ~8 bits for full byte range, got %f", h)
	}
}

func TestObfuscationScore_DetectsShortNames(t *testing.T) {
	hi := obfuscationScore("a", "Lc/d/e/F;->a()V", []string{"VGhpc0lzU29tZUVuY29kZWRTdHJpbmcK"}, nil)
	lo := obfuscationScore("computeChecksum", "Lcom/example/util/Hasher;->computeChecksum()V", []string{"hello"}, nil)
	if hi <= lo {
		t.Fatalf("expected hi > lo, got hi=%f lo=%f", hi, lo)
	}
}

func TestNameQuality_Range(t *testing.T) {
	if q := nameQuality("a", "Lc/d/F;->a()V"); q >= 0.6 {
		t.Fatalf("single-letter name should have low quality, got %f", q)
	}
	if q := nameQuality("computeChecksum", "Lcom/example/Hash;->computeChecksum()V"); q < 0.7 {
		t.Fatalf("descriptive name should have high quality, got %f", q)
	}
}

func TestScorer_Determinism(t *testing.T) {
	m := &fakeMethod{name: "x", sig: "La;->x()V", insn: 4, body: []string{"return-void"}, app: true}
	s := NewScorer()
	a := s.Score(m)
	b := s.Score(m)
	if math.Abs(a.Final-b.Final) > 1e-9 {
		t.Fatalf("expected determinism, got %f vs %f", a.Final, b.Final)
	}
}

func TestScoreBatch_ParallelMatchesSerial(t *testing.T) {
	methods := []MethodView{
		&fakeMethod{name: "a", sig: "La;->a()V", insn: 1, body: []string{"return-void"}},
		&fakeMethod{name: "b", sig: "Lb;->b()V", insn: 1, body: []string{"if-eqz v0, :end", "return-void"}},
		&fakeMethod{name: "c", sig: "Lc;->c()V", insn: 1, body: []string{"invoke-static {}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)V"}},
	}
	s := NewScorer()
	serial := make([]Score, len(methods))
	for i, m := range methods {
		serial[i] = s.Score(m)
	}
	parallel := s.ScoreBatch(methods, 4)
	for i := range methods {
		if math.Abs(serial[i].Final-parallel[i].Final) > 1e-9 {
			t.Fatalf("mismatch at %d: serial=%f parallel=%f", i, serial[i].Final, parallel[i].Final)
		}
	}
}

func TestBigramEntropy_Sane(t *testing.T) {
	if h := bigramEntropy(""); h != 0 {
		t.Fatalf("empty should be 0, got %f", h)
	}
	if h := bigramEntropy("abababab"); h <= 0 || h > 1 {
		t.Fatalf("expected low bigram entropy for periodic input, got %f", h)
	}
}
