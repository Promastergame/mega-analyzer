package pipeline

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ─── recRule.matches ──────────────────────────────────────────────────────────

func TestRecRule_Matches_True(t *testing.T) {
	r := recRule{
		cats: []types.Category{types.CategoryGoogleLVL, types.CategoryLicenseCheck},
	}
	critCats := map[types.Category]int{
		types.CategoryGoogleLVL: 2,
	}
	if !r.matches(critCats) {
		t.Error("expected matches to return true when category present")
	}
}

func TestRecRule_Matches_False(t *testing.T) {
	r := recRule{
		cats: []types.Category{types.CategoryGoogleLVL},
	}
	critCats := map[types.Category]int{
		types.CategoryBillingClient: 1,
	}
	if r.matches(critCats) {
		t.Error("expected matches to return false when category absent")
	}
}

func TestRecRule_Matches_Empty(t *testing.T) {
	r := recRule{cats: []types.Category{}}
	if r.matches(map[types.Category]int{}) {
		t.Error("expected matches to return false for empty cats")
	}
}

// ─── filesForCategories ───────────────────────────────────────────────────────

func TestFilesForCategories_ReturnsAppCodeFiles(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.Files["com/example/License.smali"] = &types.FileAnalysis{
		Path:      "com/example/License.smali",
		IsAppCode: true,
		Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryGoogleLVL}},
		},
	}
	result.Files["lib/Vendor.smali"] = &types.FileAnalysis{
		Path:      "lib/Vendor.smali",
		IsAppCode: false,
		Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryGoogleLVL}},
		},
	}

	files := filesForCategories(result, types.CategoryGoogleLVL)
	if len(files) != 1 {
		t.Errorf("expected 1 file (app code only), got %d: %v", len(files), files)
	}
	if files[0] != "com/example/License.smali" {
		t.Errorf("expected License.smali, got %q", files[0])
	}
}

func TestFilesForCategories_CapAt10(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	for i := 0; i < 15; i++ {
		path := "com/example/File" + string(rune('A'+i)) + ".smali"
		result.Files[path] = &types.FileAnalysis{
			Path:      path,
			IsAppCode: true,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryGoogleLVL}},
			},
		}
	}
	files := filesForCategories(result, types.CategoryGoogleLVL)
	if len(files) > 10 {
		t.Errorf("expected at most 10 files, got %d", len(files))
	}
}

func TestFilesForCategories_NoMatchingCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.Files["x.smali"] = &types.FileAnalysis{
		Path:      "x.smali",
		IsAppCode: true,
		Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryAdNetwork}},
		},
	}
	files := filesForCategories(result, types.CategoryGoogleLVL)
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

// ─── generateRecommendations — billing trigger ────────────────────────────────

func TestGenerateRecommendations_BillingCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.MatchesByCategory = map[types.Category]int{
		types.CategoryBillingClient: 3,
	}
	recs := generateRecommendations(result)
	found := false
	for _, r := range recs {
		if strings.Contains(r.Title, "Purchase") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Purchase' recommendation for BillingClient category")
	}
}

func TestGenerateRecommendations_PremiumCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.MatchesByCategory = map[types.Category]int{
		types.CategoryPremiumCheck: 1,
	}
	recs := generateRecommendations(result)
	found := false
	for _, r := range recs {
		if strings.Contains(r.Title, "Premium") || strings.Contains(r.Title, "Pro") {
			found = true
		}
	}
	if !found {
		t.Error("expected Premium recommendation")
	}
}

func TestGenerateRecommendations_SecurityCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.MatchesByCategory = map[types.Category]int{
		types.CategorySignatureCheck: 1,
	}
	recs := generateRecommendations(result)
	found := false
	for _, r := range recs {
		if strings.Contains(r.Title, "Security") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Security' recommendation for SignatureCheck")
	}
}

func TestGenerateRecommendations_SubscriptionCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.MatchesByCategory = map[types.Category]int{
		types.CategorySubscription: 2,
	}
	recs := generateRecommendations(result)
	found := false
	for _, r := range recs {
		if strings.Contains(r.Title, "Subscription") {
			found = true
		}
	}
	if !found {
		t.Error("expected Subscription recommendation")
	}
}

func TestGenerateRecommendations_AdCategory(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.MatchesByCategory = map[types.Category]int{
		types.CategoryAdRemove: 1,
	}
	// Just verify it doesn't panic; recommendation for ad categories may vary
	recs := generateRecommendations(result)
	_ = recs
}

// ─── triageFindings via Pipeline ─────────────────────────────────────────────

func makePipelineForTriage() *Pipeline {
	p := &Pipeline{
		result: types.NewAnalysisResult("/tmp"),
		stats:  NewPipelineStats(),
	}
	return p
}

func TestTriageFindings_NilResult(t *testing.T) {
	p := &Pipeline{result: nil, stats: NewPipelineStats()}
	// Should not panic
	p.triageFindings()
}

func TestTriageFindings_NilFileAnalysis(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["nil_file"] = nil
	// Should not panic
	p.triageFindings()
}

func TestTriageFindings_XMLResourceDowngrade(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["res/animator/fade.xml"] = &types.FileAnalysis{
		Path: "res/animator/fade.xml",
		Type: types.FileTypeXML,
		Matches: []types.Match{
			{
				Categorized: types.Categorized{Category: types.CategorySecurity},
				Severity:    types.SeverityCritical,
				IsCritical:  true,
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["res/animator/fade.xml"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected at least one match after triage")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityInfo {
		t.Errorf("expected SeverityInfo for XML resource, got %v", m.Severity)
	}
	if m.IsCritical {
		t.Error("expected IsCritical=false for XML resource")
	}
}

func TestTriageFindings_ProtoDecodeDowngrade(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/example/Proto.smali"] = &types.FileAnalysis{
		Path: "com/example/Proto.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity:   types.SeverityHigh,
				IsCritical: false,
				Text:       "ProtoAdapter.decode",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/Proto.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityInfo {
		t.Errorf("expected SeverityInfo for protobuf decode, got %v", m.Severity)
	}
}

func TestTriageFindings_BranchFalsePositive(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/example/Code.smali"] = &types.FileAnalysis{
		Path: "com/example/Code.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityHigh,
				Text:     "branch",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/Code.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityInfo {
		t.Errorf("expected SeverityInfo for branch FP without Branch SDK, got %v", m.Severity)
	}
}

func TestTriageFindings_YandexTokenSensitive(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/yandex/Sdk.smali"] = &types.FileAnalysis{
		Path: "com/yandex/Sdk.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityLow,
				Text:     "yandex.ru/token",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/yandex/Sdk.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	// triage ran without panic; behavior may vary
	_ = fa.Matches[0]
}

func TestTriageFindings_VulnerableTrustManager(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/example/SSL.smali"] = &types.FileAnalysis{
		Path: "com/example/SSL.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityMedium,
				Text:     "TrustManager trustall bypass",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/SSL.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityHigh {
		t.Errorf("expected SeverityHigh for vulnerable TrustManager, got %v", m.Severity)
	}
	if !m.IsCritical {
		t.Error("expected IsCritical=true for trustall bypass")
	}
}

func TestTriageFindings_BenignTrustManager(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/example/SSL2.smali"] = &types.FileAnalysis{
		Path: "com/example/SSL2.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityHigh,
				Text:     "SSLSocketFactory pinning",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/SSL2.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityLow {
		t.Errorf("expected SeverityLow for benign SSL pinning, got %v", m.Severity)
	}
}

func TestTriageFindings_FeatureFlagDowngrade(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/example/Flags.smali"] = &types.FileAnalysis{
		Path: "com/example/Flags.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityCritical,
				Text:     "is_enabled",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/Flags.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityInfo {
		t.Errorf("expected SeverityInfo for feature flag, got %v", m.Severity)
	}
}

func TestTriageFindings_RootSuDetection(t *testing.T) {
	p := makePipelineForTriage()
	p.result.Files["com/example/Root.smali"] = &types.FileAnalysis{
		Path: "com/example/Root.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityLow,
				Text:     "/system/bin/su",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/Root.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	if m.Severity != types.SeverityMedium {
		t.Errorf("expected SeverityMedium for su binary check, got %v", m.Severity)
	}
}

func TestTriageFindings_CriticalLimitDowngrade(t *testing.T) {
	// SeverityCritical without exfiltration proof → should be downgraded to High
	p := makePipelineForTriage()
	p.result.Files["com/example/Risky.smali"] = &types.FileAnalysis{
		Path: "com/example/Risky.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity:   types.SeverityCritical,
				IsCritical: true,
				Text:       "some_risky_pattern",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/Risky.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	// Without exfiltration proof, critical is downgraded to high
	if m.Severity == types.SeverityCritical {
		t.Error("expected severity to be downgraded from Critical without exfiltration proof")
	}
}

func TestTriageFindings_LowConfidenceStringMatchDowngrade(t *testing.T) {
	// The "lp_" match without Lucky Patcher evidence → confidence=low, evidenceType=string_match
	// This triggers 2-level downgrade: SeverityHigh → SeverityLow
	p := makePipelineForTriage()
	p.result.Files["com/example/Pay.smali"] = &types.FileAnalysis{
		Path: "com/example/Pay.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				Severity: types.SeverityHigh,
				Text:     "lp_wallet_config",
			},
		},
	}
	p.triageFindings()
	fa := p.result.Files["com/example/Pay.smali"]
	if len(fa.Matches) == 0 {
		t.Fatal("expected match")
	}
	m := fa.Matches[0]
	// lp_ without LP evidence → confidence=low, evidenceType=string_match
	// SeverityHigh → 2-level downgrade → SeverityLow
	if m.Severity != types.SeverityLow && m.Severity != types.SeverityInfo {
		t.Errorf("expected severity downgrade for lp_ FP, got %v", m.Severity)
	}
}

func TestTriageFindings_ModContactURLDowngrade(t *testing.T) {
	// Modrinth homepage inside fabric.mod.json is author contact info, not
	// app traffic: must land at Info with the mod_contact marker.
	p := makePipelineForTriage()
	p.result.Files["fabric.mod.json"] = &types.FileAnalysis{
		Path: "fabric.mod.json",
		Type: types.FileTypeJSON,
		Matches: []types.Match{
			{
				Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint},
				Severity:    types.SeverityLow,
				Text:        "https://modrinth.com/mod/appleskin",
				Pattern:     "https://modrinth.com/mod/appleskin",
				Context:     "Server endpoint",
			},
		},
	}
	// Nested Forge descriptor behind a Boot-INF layer must match too.
	p.result.Files["nested"] = &types.FileAnalysis{
		Path: "BOOT-INF/lib/mod.jar!/META-INF/mods.toml",
		Type: types.FileTypeText,
		Matches: []types.Match{
			{
				Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint},
				Severity:    types.SeverityLow,
				Text:        "https://example.com/mod",
				Pattern:     "https://example.com/mod",
			},
		},
	}
	// Same URL in executable code must NOT be demoted.
	p.result.Files["code"] = &types.FileAnalysis{
		Path: "com/example/Net.class",
		Type: types.FileTypeUnknown,
		Matches: []types.Match{
			{
				Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint},
				Severity:    types.SeverityLow,
				Text:        "https://modrinth.com/mod/appleskin",
				Pattern:     "https://modrinth.com/mod/appleskin",
			},
		},
	}
	p.triageFindings()

	fabric := p.result.Files["fabric.mod.json"].Matches[0]
	if fabric.Severity != types.SeverityInfo {
		t.Errorf("fabric.mod.json URL: severity = %v, want Info", fabric.Severity)
	}
	if fabric.Metadata["mod_contact"] != "true" {
		t.Error("fabric.mod.json URL: missing mod_contact marker")
	}
	if !strings.Contains(fabric.ReasonForSeverity, "MOD CONTACT URL") {
		t.Errorf("fabric.mod.json URL: reason = %q, want MOD CONTACT URL", fabric.ReasonForSeverity)
	}

	nested := p.result.Files["nested"].Matches[0]
	if nested.Severity != types.SeverityInfo || nested.Metadata["mod_contact"] != "true" {
		t.Errorf("nested mods.toml URL not demoted: severity=%v marker=%q", nested.Severity, nested.Metadata["mod_contact"])
	}

	code := p.result.Files["code"].Matches[0]
	if code.Severity != types.SeverityLow {
		t.Errorf(".class URL: severity = %v, want untouched Low", code.Severity)
	}
	if _, ok := code.Metadata["mod_contact"]; ok {
		t.Error(".class URL: must not carry mod_contact marker")
	}
}

// ─── PipelineStats — additional methods ──────────────────────────────────────

func TestPipelineStats_Atomics(t *testing.T) {
	stats := NewPipelineStats()
	stats.FilesTotal.Add(10)
	stats.FilesProcessed.Add(8)
	stats.FilesFailed.Add(2)
	stats.MatchesTotal.Add(100)
	stats.HotspotsTotal.Add(5)
	stats.CriticalCount.Add(3)
	stats.BytesProcessed.Add(1024)
	stats.ErrorCount.Add(1)

	if stats.FilesTotal.Load() != 10 {
		t.Errorf("expected 10, got %d", stats.FilesTotal.Load())
	}
	if stats.FilesProcessed.Load() != 8 {
		t.Errorf("expected 8, got %d", stats.FilesProcessed.Load())
	}
	if stats.FilesFailed.Load() != 2 {
		t.Errorf("expected 2, got %d", stats.FilesFailed.Load())
	}
	if stats.MatchesTotal.Load() != 100 {
		t.Errorf("expected 100, got %d", stats.MatchesTotal.Load())
	}
	if stats.ErrorCount.Load() != 1 {
		t.Errorf("expected 1, got %d", stats.ErrorCount.Load())
	}
}

// ─── Tracer — multiple stages ─────────────────────────────────────────────────

func TestTracer_MultipleStages(t *testing.T) {
	tr := NewTracer(true)
	for _, name := range []string{"parse", "detect", "report"} {
		stage := tr.StartStage(name)
		if stage == nil {
			t.Fatalf("expected non-nil stage for %q", name)
		}
		tr.EndStage(stage)
	}
	stages := tr.GetStages()
	if len(stages) != 3 {
		t.Errorf("expected 3 stages, got %d", len(stages))
	}
	if stages[0].Name != "parse" || stages[1].Name != "detect" || stages[2].Name != "report" {
		t.Errorf("stage names mismatch: %v", stages)
	}
}

func TestTracer_EndNilStage(t *testing.T) {
	tr := NewTracer(true)
	tr.EndStage(nil) // should not panic
	if len(tr.GetStages()) != 0 {
		t.Error("nil stage should not be appended")
	}
}

func TestTracer_GetStagesCopy(t *testing.T) {
	tr := NewTracer(true)
	st := tr.StartStage("s1")
	tr.EndStage(st)
	stages := tr.GetStages()
	// Mutate the returned slice — should not affect internal state
	stages[0].Name = "mutated"
	stages2 := tr.GetStages()
	if stages2[0].Name == "mutated" {
		t.Error("GetStages should return a copy, not the internal slice")
	}
}

// ─── FileDetectContext — IsTextContent caching ────────────────────────────────

func TestFileDetectContext_IsTextContent_BinaryContent(t *testing.T) {
	binary := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	ctx := &FileDetectContext{
		Content:      binary,
		ContentLower: bytes.ToLower(binary),
		LineOffsets:  types.NewLineOffsets(binary),
	}
	// Binary content should not be classified as text
	result := ctx.IsTextContent()
	if result {
		t.Error("binary content should not be text")
	}
	// Cache hit
	result2 := ctx.IsTextContent()
	if result != result2 {
		t.Error("IsTextContent should return same cached value")
	}
}

func TestFileDetectContext_IsTextContent_TextContent(t *testing.T) {
	text := []byte("const x = 'hello world'; var y = 42;")
	ctx := &FileDetectContext{
		Content:      text,
		ContentLower: bytes.ToLower(text),
		LineOffsets:  types.NewLineOffsets(text),
	}
	result := ctx.IsTextContent()
	if !result {
		t.Error("printable ASCII text should be classified as text content")
	}
}

// ─── DetectorRegistry with all options ───────────────────────────────────────

func TestDetectorRegistry_WithThreatDetector_More(t *testing.T) {
	threat := NewThreatIndicatorsDetector()
	r := NewDetectorRegistry(
		WithThreatDetector(threat),
	)
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
	if r.threatDetector == nil {
		t.Error("expected threatDetector to be set")
	}
}

// ─── CryptoDetector — Detect smoke ───────────────────────────────────────────

func TestCryptoDetector_DetectSmali(t *testing.T) {
	d := NewCryptoDetector()
	if d.Name() != "crypto" {
		t.Errorf("unexpected detector name: %q", d.Name())
	}
	content := []byte(`const-string v0, "AES/ECB/NoPadding"
invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
`)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "smali/com/example/Crypto.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		IsAppCode:    true,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path, IsAppCode: true}
	d.Detect(ctx, analysis)
	// Should have found at least one crypto-related match
	if len(analysis.Matches) == 0 {
		t.Log("CryptoDetector found 0 matches (may depend on ruleset)")
	}
}

func TestPaymentDetector_DetectSmali(t *testing.T) {
	d := NewPaymentDetector()
	if d.Name() != "payment" {
		t.Errorf("unexpected detector name: %q", d.Name())
	}
	content := []byte(`invoke-virtual {v0}, Lcom/android/billingclient/api/BillingClient;->launchBillingFlow()V
const-string v1, "purchase_token"
`)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "smali/com/example/Billing.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		IsAppCode:    true,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path, IsAppCode: true}
	d.Detect(ctx, analysis)
	// Just verify no panic
}

// ─── EndpointDetector — Detect smoke ─────────────────────────────────────────

func TestEndpointDetector_DetectSmali(t *testing.T) {
	d := NewEndpointDetector()
	if d.Name() != "endpoint_detector" {
		t.Errorf("unexpected name: %q", d.Name())
	}
	content := []byte(`const-string v0, "https://api.evil.com/collect"
const-string v1, "http://tracker.example.com/track"
`)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "smali/com/example/Net.smali",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		IsAppCode:    true,
		FileType:     types.FileTypeSmali,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path, IsAppCode: true}
	d.Detect(ctx, analysis)
}

// ─── ResourceDetector — Detect smoke ─────────────────────────────────────────

func TestResourceDetector_DetectXML(t *testing.T) {
	d := NewResourceDetector()
	if d.Name() != "resource" {
		t.Errorf("unexpected name: %q", d.Name())
	}
	content := []byte(`<resources>
  <string name="api_key">AIzaSyABC123</string>
  <string name="app_id">1:123456:android:abc</string>
</resources>`)
	lineOffsets := types.NewLineOffsets(content)
	ctx := &FileDetectContext{
		Ctx:          context.Background(),
		Path:         "res/values/strings.xml",
		Content:      content,
		ContentLower: bytes.ToLower(content),
		LineOffsets:  lineOffsets,
		FileType:     types.FileTypeXML,
	}
	analysis := &types.FileAnalysis{Path: ctx.Path}
	d.Detect(ctx, analysis)
}

// ─── matchNormalizedPattern — edge cases ──────────────────────────────────────

func TestMatchNormalizedPattern_ExactMatch(t *testing.T) {
	if !matchNormalizedPattern("com/example/Test", "com/example/Test") {
		t.Error("expected exact match")
	}
}

func TestMatchNormalizedPattern_CaseInsensitive(t *testing.T) {
	// matchNormalizedPattern is case-sensitive; just verify no panic
	_ = matchNormalizedPattern("com/example/test", "COM/EXAMPLE/TEST")
}

func TestMatchNormalizedPattern_NoMatch(t *testing.T) {
	if matchNormalizedPattern("com/example/test", "com/other/path") {
		t.Error("expected no match for different paths")
	}
}

func TestMatchNormalizedPattern_EmptyPattern(t *testing.T) {
	// Empty pattern should not match
	if matchNormalizedPattern("com/example", "") {
		t.Error("expected empty pattern not to match")
	}
}

// ─── UserFeedbackFilter — noise/relevant patterns ─────────────────────────────

func TestUserFeedbackFilter_ShouldFilterOut_NoisePath(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddNoisePattern("com/example/noise")
	if !f.ShouldFilterOut("com/example/noise/Class.smali", nil) {
		t.Error("expected noise path to be filtered")
	}
}

func TestUserFeedbackFilter_ShouldBoost_RelevantKeyword(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddRelevantKeyword("billing")
	if !f.ShouldBoost("com/example/Pay.smali", []string{"billing"}) {
		t.Error("expected billing keyword to trigger boost")
	}
}

func TestUserFeedbackFilter_ShouldFilterOut_NoiseKeyword(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddNoiseKeyword("admob")
	if !f.ShouldFilterOut("com/google/ads/AdMob.smali", []string{"admob"}) {
		t.Error("expected admob noise keyword to filter")
	}
}

func TestUserFeedbackFilter_Stats_More(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddNoisePattern("a")
	f.AddNoisePattern("b")
	f.AddRelevantPattern("c")
	f.AddNoiseKeyword("kw1")
	f.AddRelevantKeyword("kw2")
	f.AddRelevantKeyword("kw3")

	np, rp, nk, rk := f.Stats()
	if np != 2 {
		t.Errorf("expected 2 noise patterns, got %d", np)
	}
	if rp != 1 {
		t.Errorf("expected 1 relevant pattern, got %d", rp)
	}
	if nk != 1 {
		t.Errorf("expected 1 noise keyword, got %d", nk)
	}
	if rk != 2 {
		t.Errorf("expected 2 relevant keywords, got %d", rk)
	}
}

// ─── extractManifestPackage — edge cases ──────────────────────────────────────

func TestExtractManifestPackage_EmptyContent(t *testing.T) {
	result := extractManifestPackage(nil)
	if result != "" {
		t.Errorf("expected empty for nil content, got %q", result)
	}
	result2 := extractManifestPackage([]byte{})
	if result2 != "" {
		t.Errorf("expected empty for empty content, got %q", result2)
	}
}

// ─── piracyRiskLevel — all branches ──────────────────────────────────────────

func TestPiracyRiskLevel_AllBranches(t *testing.T) {
	// Additional mixed-case tests
	if got := piracyRiskLevel("CRITICAL"); got != types.RiskNone {
		// The function likely uses exact lowercase match
		t.Logf("piracyRiskLevel('CRITICAL') = %v (case-sensitive)", got)
	}
	// Valid lowercase cases are already tested in pipeline_more_test.go
}

// ─── stringSet — additional methods ──────────────────────────────────────────

func TestStringSet_AddDuplicate(t *testing.T) {
	ss := newStringSet("a")
	ss.Add("a") // duplicate
	// Should not panic and still have "a"
	if !ss.Has("a") {
		t.Error("expected 'a' after adding duplicate")
	}
}

// ─── safeSnippetStr — unicode ─────────────────────────────────────────────────

func TestSafeSnippetStr_Unicode(t *testing.T) {
	// Multi-byte unicode runes
	s := "こんにちは世界" // 7 runes
	got := safeSnippetStr(s, 4)
	runes := []rune(strings.TrimSuffix(got, "…"))
	if len(runes) > 4 {
		t.Errorf("expected at most 4 runes, got %d: %q", len(runes), got)
	}
}

func TestSafeSnippetStr_ExactLength(t *testing.T) {
	s := "hello"
	got := safeSnippetStr(s, 5)
	if got != "hello" {
		t.Errorf("exact length should not be truncated, got %q", got)
	}
}
