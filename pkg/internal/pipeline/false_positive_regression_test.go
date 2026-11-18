package pipeline

import (
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
	"strings"
	"testing"
)

func TestKeywordGateUsesPatternWithinSnippet(t *testing.T) {
	for _, tc := range []struct {
		pattern, text string
		keep          bool
	}{
		{"powershell", "application/PowerShell", true},
		{"superuser", "isSuperuserEnabled", false},
		{"accessibilityservice", "getEnabledAccessibilityServiceList", false},
		{"accessibilityservice", "Landroid/accessibilityservice/AccessibilityService;", true},
	} {
		m := types.Match{Categorized: types.Categorized{Category: types.CategoryCustomKeyword}, Pattern: tc.pattern, Text: tc.text}
		if got := precisionGateKeeps("smali/com/example/Test.smali", &m); got != tc.keep {
			t.Errorf("%s in %s: got %v, want %v", tc.pattern, tc.text, got, tc.keep)
		}
	}
}
func TestCommonIntentSchemes(t *testing.T) {
	for _, s := range []string{"content", "file", "mailto", "tel", "https"} {
		if !isCommonIntentScheme(s) {
			t.Errorf("%s should be excluded", s)
		}
	}
	if isCommonIntentScheme("mycustomscheme") {
		t.Error("custom scheme must remain checked")
	}
}
func TestSAXReferenceNotEndpoint(t *testing.T) {
	if !isKnownNonEndpointHTTPReference([]byte("http://xml.org/sax/features/namespaces")) {
		t.Error("SAX feature URI is an identifier")
	}
	if isKnownNonEndpointHTTPReference([]byte("http://example.com/api")) {
		t.Error("actual endpoint should remain checked")
	}
}

func TestAccessibilityCallMustUseReceiverAndExactMethod(t *testing.T) {
	for _, tc := range []struct {
		line, method string
		want         bool
	}{
		{"invoke-virtual {v0}, Landroid/accessibilityservice/AccessibilityService;->getWindows()Ljava/util/List;", "getwindows", true},
		{"invoke-virtual {v0}, Landroid/view/View;->getWindowSystemUiVisibility()I", "getwindows", false},
		{"invoke-virtual {v0}, Landroid/view/View;->getWindows()Ljava/util/List;", "getwindows", false},
	} {
		content := toLowerBytes([]byte(tc.line))
		idx := strings.Index(string(content), tc.method)
		if got := isAccessibilityCall(content, idx, tc.method); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.line, got, tc.want)
		}
	}
}
func TestPiracyIndicatorIsNotMalwareByItself(t *testing.T) {
	for _, cat := range []types.Category{types.CategoryPiracy, types.CategoryPiracySite, types.CategoryCrackTool, types.CategoryPiracyTool} {
		if got := findingKind(cat); got != finding.KindInventory {
			t.Errorf("%s kind=%s, want inventory", cat, got)
		}
	}
	if got := findingKind(types.CategoryMalwareCombo); got != finding.KindMalware {
		t.Errorf("malware must retain malware kind, got %s", got)
	}
}
func TestObfuscatorNotKeyguard(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{{"android.permission.KEYGUARD", false}, {"keyguard; yguard", true}} {
		data := []byte(tc.body)
		ctx := createDetectorCtx("res/values/strings.xml", data, types.FileTypeXML)
		a := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(data)))
		NewObfuscationDetector().Detect(ctx, a)
		if got := hasMatchCategory(a.Matches, types.CategoryObfuscator); got != tc.want {
			t.Errorf("%q got %v want %v", tc.body, got, tc.want)
		}
	}
}
func TestFileScopedPrefersAppAndKeepsLibraryFinding(t *testing.T) {
	p := comboTestPipeline(t)
	lib := p.result.Files["b/10_alpha.smali"]
	lib.IsLibrary = true
	app := p.result.Files["c/20_alpha_beta.smali"]
	app.IsAppCode = true
	for _, r := range p.evaluateFileScopedCombos(nil) {
		if r.RuleID == "r_alpha" && r.MatchedFile != app.Path {
			t.Errorf("app should win: %+v", r)
		}
	}
	app.IsAppCode = false
	delete(p.result.Files, "c/20_alpha_beta.smali")
	for _, r := range p.evaluateFileScopedCombos(nil) {
		if r.RuleID == "r_alpha" && (r.MatchedFile != lib.Path || len(r.Limitations) == 0) {
			t.Errorf("library finding should be retained and annotated: %+v", r)
		}
	}
}

func TestAccessibilityFindsValidCallAfterNoise(t *testing.T) {
	content := toLowerBytes([]byte("Landroid/view/View;->getWindowSystemUiVisibility()I\nLandroid/accessibilityservice/AccessibilityService;->getWindows()Ljava/util/List;"))
	if findAccessibilityCall(content, "getwindows") < 0 {
		t.Fatal("valid call after substring noise was missed")
	}
}
