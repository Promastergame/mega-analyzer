package ml

// Regression: a trivial boolean premium getter (the single most common
// license-gate shape in the wild — cf. Plague Inc PurchaseManager.isPremium)
// must survive the predictor pipeline as a patch point instead of being
// eaten by noise filtering or the score floor.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const smaliPremiumGetter = `.class public Lcom/example/PurchaseManager;
.super Ljava/lang/Object;

.field private isPremium:Z

.method public isPremium()Z
    .registers 1
    iget-boolean v0, p0, Lcom/example/PurchaseManager;->isPremium:Z
    return v0
.end method

.method public setPremium(Z)V
    .registers 2
    iput-boolean p1, p0, Lcom/example/PurchaseManager;->isPremium:Z
    return-void
.end method
`

func predictSingleSmali(t *testing.T, name, content string) *PatchPrediction {
	t.Helper()
	dir := testTempDir(t)
	sub := filepath.Join(dir, "smali", "com", "example")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultPredictorConfig()
	cfg.Mode = "research"
	p := NewPatchPredictorWithConfig(&bytes.Buffer{}, cfg)
	pred, err := p.PredictFromDirectory(dir)
	if err != nil {
		t.Fatalf("PredictFromDirectory: %v", err)
	}
	return pred
}

func allPatchPoints(pred *PatchPrediction) []PatchPoint {
	var out []PatchPoint
	out = append(out, pred.HighRisk...)
	out = append(out, pred.MediumRisk...)
	out = append(out, pred.LowRisk...)
	return out
}

func TestPremiumBooleanGetterIsPatchPoint(t *testing.T) {
	pred := predictSingleSmali(t, "PurchaseManager.smali", smaliPremiumGetter)
	for _, pt := range allPatchPoints(pred) {
		if strings.Contains(pt.MethodName, "isPremium") {
			return // found
		}
	}
	t.Fatalf("isPremium()Z missing from patch points (high=%d med=%d low=%d)",
		len(pred.HighRisk), len(pred.MediumRisk), len(pred.LowRisk))
}
