package analyzer

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/parser"
)

func TestFeatureOnlyAnalysisPreservesPipelineInputs(t *testing.T) {
	class, err := parser.NewSmaliParser(`.class public Lapp/Check;
.super Ljava/lang/Object;
.method public checkLicense()Z
.registers 2
const/4 v0, 0x1
if-eqz v0, :no
return v0
:no
const/4 v0, 0x0
return v0
.end method
`).Parse()
	if err != nil {
		t.Fatal(err)
	}
	a := NewDefaultMethodAnalyzer()
	full := a.Analyze(&class.Methods[0], class)
	features := a.AnalyzeFeatures(&class.Methods[0], class)
	if !reflect.DeepEqual(full.FeatureMap, features.FeatureMap) || full.WeightedScore != features.WeightedScore || full.RiskLevel != features.RiskLevel {
		t.Fatal("feature-only path changed the role/scoring inputs")
	}
	if full.CFG == nil || features.CFG != nil {
		t.Fatal("feature-only path must avoid the discarded CFG")
	}
}
