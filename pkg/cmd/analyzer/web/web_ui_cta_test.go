package web

import (
	"regexp"
	"strings"
	"testing"
)

// Presentation assertions inspect a complete rule, independent of formatting.
// The workbench uses one component layer rather than a base/override cascade.
func workbenchRule(t *testing.T, selector string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(mustAsset("assets/app.css"))
	if len(m) != 2 {
		t.Fatalf("missing CSS rule: %s", selector)
	}
	return m[1]
}

func workbenchDeclaration(t *testing.T, selector, property, value string) {
	t.Helper()
	rule := workbenchRule(t, selector)
	re := regexp.MustCompile(`(?:^|;)\s*` + regexp.QuoteMeta(property) + `\s*:\s*` + regexp.QuoteMeta(value) + `\s*(?:;|$)`)
	if !re.MatchString(rule) {
		t.Errorf("%s must declare %s: %s", selector, property, value)
	}
}

func TestPrimaryActionUsesWorkbenchTokens(t *testing.T) {
	for property, value := range map[string]string{
		"background": "var(--action)",
		"color": "var(--on-action)",
		"border-radius": "8px",
		"min-height": "48px",
		"box-shadow": "none",
	} {
		workbenchDeclaration(t, ".scan-btn", property, value)
	}
}

func TestPrimaryActionHasNoDecorativeGradient(t *testing.T) {
	for _, selector := range []string{".scan-btn", ".scan-btn:hover:not(:disabled)", ".scan-btn.stop"} {
		rule := workbenchRule(t, selector)
		if strings.Contains(rule, "gradient") || strings.Contains(rule, "text-shadow") {
			t.Errorf("decorative effects in %s", selector)
		}
	}
}

func TestPrimaryActionDisabledIsReadable(t *testing.T) {
	workbenchDeclaration(t, ".scan-btn:disabled", "opacity", "1")
	workbenchDeclaration(t, ".scan-btn:disabled", "color", "var(--dim)")
	workbenchDeclaration(t, ".scan-btn:disabled", "background", "transparent")
	if !strings.Contains(mustAsset("assets/index.html"), `aria-describedby="runNote"`) {
		t.Error("the disabled action needs an explanation")
	}
}

func TestPrimaryActionDoesNotLiftOnHover(t *testing.T) {
	workbenchDeclaration(t, ".scan-btn:hover:not(:disabled)", "transform", "none")
	workbenchDeclaration(t, ".scan-btn:hover:not(:disabled)", "box-shadow", "none")
}

func TestStopUsesSemanticColour(t *testing.T) {
	workbenchDeclaration(t, ".scan-btn.stop", "background", "transparent")
	workbenchDeclaration(t, ".scan-btn.stop", "color", "var(--red)")
	workbenchDeclaration(t, ".scan-btn.stop", "border-color", "var(--red)")
}

func TestProgressReadoutIsFlat(t *testing.T) {
	workbenchDeclaration(t, ".pb", "background", "var(--accent)")
}

func TestPrimaryActionHasOneBaseDefinition(t *testing.T) {
	re := regexp.MustCompile(`(?m)^\.scan-btn\s*\{`)
	if n := len(re.FindAllString(mustAsset("assets/app.css"), -1)); n != 1 {
		t.Errorf("expected one authoritative action rule, got %d", n)
	}
}

func TestAppearanceRespectsSystemPreference(t *testing.T) {
	css := mustAsset("assets/app.css")
	for _, marker := range []string{`@media(prefers-color-scheme:dark)`, `:root[data-theme="dark"]`, `:root:not([data-theme="light"])`} {
		if !strings.Contains(css, marker) {
			t.Errorf("appearance support missing: %s", marker)
		}
	}
}
