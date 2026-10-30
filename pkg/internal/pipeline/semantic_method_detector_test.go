package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Regression: Android accessibility probes (hasAccessibility*,
// AccessibilityService, daltonizer) share the "hasaccess" substring with
// entitlement vocabulary but are OS probes — never premium gates.
// Seen in the wild: hasAccessibilityDisplayDaltonizer matched as
// "Access check" → false client_side_auth_gate chain (subwaysurf).
func TestSemanticDetector_SkipsAccessibilityProbes(t *testing.T) {
	d := NewSemanticMethodDetector()

	content := []byte(`
.class public Lgatewayprotocol/v1/DynamicDeviceInfoOuterClass$DynamicDeviceInfo$AndroidOrBuilder;
.super Ljava/lang/Object;

.method public abstract hasAccessibilityDisplayDaltonizer()Z
    # abstract
.end method
`)
	ctx := newTestContext("smali/gatewayprotocol/v1/DynamicDeviceInfoOuterClass.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	for _, m := range analysis.Matches {
		if m.Category == types.CategoryPremiumCheck {
			t.Fatalf("accessibility probe must not emit premium match, got %+v", m)
		}
	}
}

func TestSemanticDetector_KeepsRealEntitlementGate(t *testing.T) {
	d := NewSemanticMethodDetector()

	content := []byte(`
.class public Lcom/app/Billing;
.super Ljava/lang/Object;

.method public hasAccess()Z
    iget-boolean v0, p0, Lcom/app/Billing;->isPremium:Z
    return v0
.end method
`)
	ctx := newTestContext("smali/com/app/Billing.smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	d.Detect(ctx, analysis)

	found := false
	for _, m := range analysis.Matches {
		if m.Category == types.CategoryPremiumCheck && m.Pattern == "Access check" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real hasAccess gate must still match, got %+v", analysis.Matches)
	}
}
