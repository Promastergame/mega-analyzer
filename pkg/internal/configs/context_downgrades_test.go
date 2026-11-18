package configs

import (
	"encoding/json"
	"testing"

	"mega-analyzer/pkg/internal/rules"
)

// loadShippedEngine загружает все боевые наборы, как это делает пайплайн
// (см. loadRulesEngine в pkg/internal/pipeline).
func loadShippedEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e := rules.NewEngine()
	for _, name := range []string{
		"permission_rules.json",
		"malware_combos.json",
		"banking_threats.json",
		"context_downgrades.json",
	} {
		data, ok := File(name)
		if !ok || len(data) == 0 {
			t.Fatalf("%s: missing from embedded configs", name)
		}
		if err := e.LoadRulesFromBytes(name, data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return e
}

func TestContextDowngradesShipClean(t *testing.T) {
	e := loadShippedEngine(t)
	for _, issue := range e.Lint() {
		if issue.Level == rules.LintError {
			t.Errorf("lint error in %s: %s", issue.RuleID, issue.Message)
		}
	}
	if h := e.Health(); h.Degraded() {
		t.Fatalf("shipped rules are degraded: %s", h.String())
	}
}

func TestContextDowngradesPolicy(t *testing.T) {
	var doc struct {
		Rules []rules.Rule `json:"rules"`
	}
	if err := json.Unmarshal(ContextDowngrades(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) == 0 {
		t.Fatal("context_downgrades.json must ship at least one rule")
	}
	e := loadShippedEngine(t)
	for _, r := range doc.Rules {
		if !r.IsContext() {
			t.Errorf("%s: default context file must contain only kind=context", r.ID)
		}
		if len(r.Suppresses) > 0 {
			t.Errorf("%s: shipped defaults must not suppress (downgrade only)", r.ID)
		}
		if len(r.Downgrades) == 0 {
			t.Errorf("%s: context rule without targets is dead weight", r.ID)
		}
		for _, id := range r.Downgrades {
			if _, ok := e.GetRuleByID(id); !ok {
				t.Errorf("%s: downgrade target %q does not exist", r.ID, id)
			}
		}
	}
}

func TestPasswordManagerDowngradesOverlay(t *testing.T) {
	e := loadShippedEngine(t)
	ctx := &rules.ConditionContext{
		Permissions: []string{
			"android.permission.BIND_ACCESSIBILITY_SERVICE",
			"android.permission.INTERNET",
		},
		APICalls: []string{
			"AccessibilityNodeInfo",
			"performAction",
			"findAccessibilityNodeInfosByViewId",
		},
		Classes: []string{"com/bitwarden/autofill/AutofillService"},
	}
	var found *rules.RuleEvaluationResult
	for _, r := range e.EvaluateAll(ctx) {
		r := r
		if r.RuleID == "bank_overlay_a11y_modern" {
			found = &r
		}
	}
	if found == nil {
		t.Fatal("bank_overlay_a11y_modern must stay visible even when downgraded")
	}
	if found.DowngradedBy != "ctx-password-manager" {
		t.Fatalf("want downgrade by ctx-password-manager, got %+v", *found)
	}
	if found.Severity != "info" || found.Score != 0 || found.FindingKind != "inventory" {
		t.Fatalf("generic accessibility APIs must remain an inventory observation, got %+v", *found)
	}
}

func TestAccessibilityAPIsWithoutBenignContextRemainInventory(t *testing.T) {
	e := loadShippedEngine(t)
	ctx := &rules.ConditionContext{
		Permissions: []string{
			"android.permission.BIND_ACCESSIBILITY_SERVICE",
			"android.permission.INTERNET",
		},
		APICalls: []string{
			"AccessibilityNodeInfo",
			"performAction",
			"findAccessibilityNodeInfosByViewId",
		},
		Classes: []string{"com/evil/trojan/OverlayService"},
	}
	var found *rules.RuleEvaluationResult
	for _, r := range e.EvaluateAll(ctx) {
		r := r
		if r.RuleID == "bank_overlay_a11y_modern" {
			found = &r
		}
	}
	if found == nil {
		t.Fatal("bank_overlay_a11y_modern must fire without benign context")
	}
	if found.DowngradedBy != "" {
		t.Fatalf("must not be downgraded without context, got %+v", *found)
	}
	if found.Severity != "info" || found.Score != 0 || found.FindingKind != "inventory" {
		t.Fatalf("a namespace without benign context is not proof of an overlay attack: %+v", *found)
	}
}

func TestDeviceAdminDowngradesClassicOverlay(t *testing.T) {
	e := loadShippedEngine(t)
	ctx := &rules.ConditionContext{
		Permissions: []string{
			"android.permission.BIND_ACCESSIBILITY_SERVICE",
			"android.permission.SYSTEM_ALERT_WINDOW",
			"android.permission.INTERNET",
			"android.permission.BIND_DEVICE_ADMIN",
		},
		APICalls: []string{"performGlobalAction"},
	}
	var found *rules.RuleEvaluationResult
	for _, r := range e.EvaluateAll(ctx) {
		r := r
		if r.RuleID == "bank_overlay_classic" {
			found = &r
		}
	}
	if found == nil {
		t.Fatal("bank_overlay_classic must stay visible even when downgraded")
	}
	if found.DowngradedBy != "ctx-device-admin-mdm" {
		t.Fatalf("want downgrade by ctx-device-admin-mdm, got %+v", *found)
	}
}
