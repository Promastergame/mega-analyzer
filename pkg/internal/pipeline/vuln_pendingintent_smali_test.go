// pkg/internal/pipeline/vuln_pendingintent_smali_test.go
//
// Tests for the AST-based mutable-PendingIntent detector (audit P0-3 / B1).
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func runPendingIntentAST(t *testing.T, content string) []types.Match {
	t.Helper()
	d := NewVulnPendingIntentDetector()
	ctx := createDetectorCtx("smali/com/app/Alarms.smali", []byte(content), types.FileTypeSmali)
	ctx.Class = parseCryptoFixture(t, content)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	return analysis.Matches
}

func piMatches(matches []types.Match) []types.Match {
	out := make([]types.Match, 0, len(matches))
	for _, m := range matches {
		if m.Category == types.CategoryPendingIntentVuln || m.Category == types.CategoryPendingIntentReview {
			out = append(out, m)
		}
	}
	return out
}

// The regression case for B1: one safe call site must NOT suppress the
// unsafe one in the same class.
func TestPendingIntentAST_MixedSafeAndUnsafe(t *testing.T) {
	matches := piMatches(runPendingIntentAST(t, `
.class public Lcom/app/Alarms;
.method public safe()V
    .locals 4
    const/high16 v3, 0x4000000
    invoke-static {v0, v1, v2, v3}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method

.method public unsafe()V
    .locals 4
    const/4 v3, 0x0
    invoke-static {v0, v1, v2, v3}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
`))
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 finding (unsafe call site), got %d: %v",
			len(matches), getMatchSummary(matches))
	}
	if matches[0].MethodName != "unsafe" {
		t.Errorf("finding attributed to %q, want unsafe", matches[0].MethodName)
	}
	// flags=0 as a plain const is a fully-known flag value: no or-int
	// assembly can contribute extra bits, so this is the classic
	// missing-FLAG_IMMUTABLE vulnerability (eval corpus v6:
	// pi-missing-immutable / pi-mixed-safe-and-unsafe expect vuln).
	if matches[0].Category != types.CategoryPendingIntentVuln {
		t.Errorf("plain-const flags=0 must be a vuln, got %v", matches[0].Category)
	}
	if matches[0].IsCritical || matches[0].Severity != types.SeverityMedium {
		t.Error("missing-FLAG_IMMUTABLE vuln must be MEDIUM severity, not critical")
	}
}

func TestPendingIntentAST_ExplicitMutable(t *testing.T) {
	matches := piMatches(runPendingIntentAST(t, `
.class public Lcom/app/Alarms;
.method public reply()V
    .locals 4
    const/high16 v3, 0x2000000
    invoke-static {v0, v1, v2, v3}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
`))
	if len(matches) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(matches))
	}
	if matches[0].Context == "" || matches[0].Confidence != "high" {
		t.Errorf("unexpected metadata: confidence=%q", matches[0].Confidence)
	}
}

func TestPendingIntentAST_OrComposedImmutable(t *testing.T) {
	// FLAG_UPDATE_CURRENT | FLAG_IMMUTABLE composed via or-int → safe.
	matches := piMatches(runPendingIntentAST(t, `
.class public Lcom/app/Alarms;
.method public composed()V
    .locals 5
    const/high16 v3, 0x8000000
    const/high16 v4, 0x4000000
    or-int v3, v3, v4
    invoke-static {v0, v1, v2, v3}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
`))
	if len(matches) != 0 {
		t.Errorf("OR-composed FLAG_IMMUTABLE must be safe, got %d findings", len(matches))
	}
}

func TestPendingIntentAST_OrComposedMutableOnly(t *testing.T) {
	matches := piMatches(runPendingIntentAST(t, `
.class public Lcom/app/Alarms;
.method public composed()V
    .locals 5
    const/high16 v3, 0x8000000
    const/high16 v4, 0x2000000
    or-int/2addr v3, v4
    invoke-static {v0, v1, v2, v3}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
`))
	if len(matches) != 1 {
		t.Fatalf("expected 1 finding for composed-mutable flags, got %d", len(matches))
	}
}

func TestPendingIntentAST_UnresolvedFlags(t *testing.T) {
	// Flags come from a method parameter → not a constant. Medium-confidence
	// finding, not critical.
	matches := piMatches(runPendingIntentAST(t, `
.class public Lcom/app/Alarms;
.method public static create(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    .locals 1
    invoke-static {p0, p1, p2, p3}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    move-result-object v0
    return-object v0
.end method
`))
	if len(matches) != 1 {
		t.Fatalf("expected 1 unresolved-flags finding, got %d", len(matches))
	}
	if matches[0].IsCritical {
		t.Error("unresolved flags should not be critical")
	}
	if matches[0].Confidence != "low" || matches[0].Category != types.CategoryPendingIntentReview || matches[0].Severity != types.SeverityInfo {
		t.Errorf("unresolved flags must be informational review, got %#v", matches[0])
	}
	if item := typedFindingFromMatch(matches[0], ""); item.Kind != "inventory" || len(item.CWE) != 0 || item.Explanation == nil || item.Explanation.Status != "needs_review" {
		t.Errorf("unresolved flags were presented as a vulnerability: %#v", item)
	}
}

func TestPendingIntentAST_SafeOnlyNoFinding(t *testing.T) {
	matches := piMatches(runPendingIntentAST(t, `
.class public Lcom/app/Alarms;
.method public safe()V
    .locals 4
    const/high16 v3, 0x4000000
    invoke-static {v0, v1, v2, v3}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    return-void
.end method
`))
	if len(matches) != 0 {
		t.Errorf("FLAG_IMMUTABLE usage must not be flagged, got %d", len(matches))
	}
}
