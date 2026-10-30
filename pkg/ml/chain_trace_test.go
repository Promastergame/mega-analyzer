package ml

import (
	"strings"
	"testing"
)

func TestChainTracerDisabledIsNoOp(t *testing.T) {
	ct := NewChainTracer(false)
	if ct != nil {
		t.Fatal("disabled tracer must be nil")
	}
	ct.Begin("x") // must not panic on nil
	ct.Detail("k", "v")
	ct.End("done")
	if ct.Render() != "" {
		t.Fatal("nil tracer must render empty string")
	}
}

func TestRunChainMLPatchCurrencyIsDiagnosticOnly(t *testing.T) {
	mi := &MethodInfo{
		Name:       "getCoins",
		ReturnType: "I",
		ReturnsInt: true,
		Calls: []CallInfo{
			{FullCall: "Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I"},
		},
		StringConsts: []string{"coins"},
	}
	res := RunChainMLPatch(mi, ".method public getCoins()I", "()I", true)
	if res.Signals == nil || len(res.Signals.Signals) == 0 {
		t.Fatal("expected currency signal")
	}
	if res.Signals.Signals[0].Kind != VulnClientSideCurrency {
		t.Fatalf("kind = %s, want %s", res.Signals.Signals[0].Kind, VulnClientSideCurrency)
	}
	if res.Patch != "" {
		t.Fatalf("currency finding must remain diagnostic-only, got patch:\n%s", res.Patch)
	}
	if !strings.Contains(res.Trace, "CHAIN-ML-PATCH") || !strings.Contains(res.Trace, "diagnostic_only") {
		t.Fatalf("trace must record the diagnostic-only decision, got:\n%s", res.Trace)
	}
}

func TestRunChainMLPatchPremiumIsDiagnosticOnly(t *testing.T) {
	mi := &MethodInfo{
		Name:           "isPremium",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsShortMethod:  true,
		StringConsts:   []string{"premium"},
	}
	res := RunChainMLPatch(mi, ".method public isPremium()Z", "()Z", true)
	if res.Signals == nil || len(res.Signals.Signals) == 0 {
		t.Fatal("expected premium signal")
	}
	if res.Patch != "" {
		t.Fatalf("premium finding must remain diagnostic-only, got patch:\n%s", res.Patch)
	}
	if !strings.Contains(res.Trace, "diagnostic_only") || !strings.Contains(res.Trace, "access_license_or_monetization") {
		t.Fatalf("trace must record the safety decision, got:\n%s", res.Trace)
	}
}

func TestRunChainMLPatchNoTraceWhenDisabled(t *testing.T) {
	mi := &MethodInfo{Name: "isVip", ReturnType: "Z", ReturnsBoolean: true}
	res := RunChainMLPatch(mi, ".method public isVip()Z", "()Z", false)
	if res.Trace != "" {
		t.Fatal("trace must be empty when chain-ml-patch flag is off")
	}
}

func TestDetectWeakRandom(t *testing.T) {
	mi := &MethodInfo{
		Name:         "makeToken",
		Calls:        []CallInfo{{FullCall: "Ljava/util/Random;->nextInt(I)I"}},
		StringConsts: []string{"session_token"},
	}
	s := detectWeakRandom(mi)
	if s == nil || s.Kind != VulnWeakRandom {
		t.Fatal("expected weak_random signal")
	}
	if s.Severity != VulnSeverityHigh {
		t.Fatalf("token context must raise severity, got %s", s.Severity)
	}
}

func TestDetectCleartextHTTP(t *testing.T) {
	mi := &MethodInfo{
		Name:         "loadConfig",
		StringConsts: []string{"http://api.example.com/config"},
	}
	if s := detectCleartextHTTP(mi); s == nil {
		t.Fatal("expected cleartext_http signal")
	}
}

func TestValidatorFullOpcodeTable(t *testing.T) {
	sv := NewSmaliValidator()
	for _, op := range []string{
		"move-result-object", "iget-boolean", "sput-wide", "check-cast",
		"instance-of", "array-length", "monitor-enter", "throw",
		"packed-switch", "add-int/lit8", "cmpl-float", "invoke-static/range",
		"filled-new-array", "int-to-long", "const-string/jumbo",
	} {
		if _, ok := sv.opcodeTable[op]; !ok {
			t.Errorf("opcode %s missing from table", op)
		}
	}
}

func TestValidatorPRegisterOverflow(t *testing.T) {
	sv := NewSmaliValidator()
	code := `.method public check(I)Z
    .registers 3
    const/4 v0, 0x1
    if-eqz p2, :cond_0
    return v0
:cond_0
    const/4 v0, 0x0
    return v0
.end method`
	res := sv.Validate(code)
	if res.Valid {
		t.Fatal("p2 with 1 param (p0=this, p1=arg) must be rejected")
	}
}

func TestValidatorNarrowFormatRejectsV16(t *testing.T) {
	sv := NewSmaliValidator()
	code := `.method public m()V
    .registers 17
    move v16, v0
    return-void
.end method`
	res := sv.Validate(code)
	if res.Valid {
		t.Fatal("v16 in 4-bit format 12x must be rejected")
	}
}

func TestLintDuplicateLabelsAndMissingEnd(t *testing.T) {
	code := `.method public m()V
    .locals 1
    const/4 v0, 0x0
:cond_0
    return-void
:cond_0
    return-void`
	issues := LintSmaliStrict(code)
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "L7") {
		t.Errorf("expected L7 duplicate label, got: %v", issues)
	}
	if !strings.Contains(joined, "L8") {
		t.Errorf("expected L8 missing .end method, got: %v", issues)
	}
}

func TestBuildPatchTemplates(t *testing.T) {
	sv := NewSmaliValidator()
	for name, patch := range map[string]string{
		"currency": BuildCurrencyReturnPatch(".method public getGold()J", "()J", "J"),
		"premium":  BuildPremiumUnlockPatch(".method public isPro()Z", "()Z", "Z"),
		"swallow":  BuildSwallowCheckPatch(".method public showAd()V", "()V", "V"),
	} {
		if res := sv.ValidateStrict(patch); !res.Valid {
			t.Errorf("%s template must be valid: %+v\n%s", name, res.Errors, patch)
		}
	}
	// swallow на не-void методе НЕ должен писать return-void (P4)
	p := BuildSwallowCheckPatch(".method public getToken()Ljava/lang/String;", "()Ljava/lang/String;", "Ljava/lang/String;")
	if strings.Contains(p, "return-void") {
		t.Errorf("swallow on String method must not emit return-void:\n%s", p)
	}
}

func TestChainTracerRenderOrdersDetails(t *testing.T) {
	ct := NewChainTracer(true)
	ct.Begin("validation")
	ct.Detail("zeta", "last")
	ct.Detail("alpha", "first")
	ct.End("complete")

	trace := ct.Render()
	alpha := strings.Index(trace, "alpha: first")
	zeta := strings.Index(trace, "zeta: last")
	if alpha < 0 || zeta < 0 {
		t.Fatalf("expected both detail keys in trace, got:\n%s", trace)
	}
	if alpha > zeta {
		t.Fatalf("detail keys must render in sorted order, got:\n%s", trace)
	}
}
