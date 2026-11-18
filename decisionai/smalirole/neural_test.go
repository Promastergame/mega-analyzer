package smalirole

import (
	"math"
	"strings"
	"testing"
)

const neuralColorCode = ".method public static a(Landroid/widget/TextView;)V\n    .registers 3\n    const/16 v0, 0x64\n    invoke-virtual {p0, v0}, Landroid/widget/TextView;->setTextColor(I)V\n    return-void\n.end method"

func TestNeuralResultIsRawGNNWithWeightIdentity(t *testing.T) {
	model, err := LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Fatal(err)
	}
	result := AnalyzeNeural(Request{Code: neuralColorCode, Line: 3, Class: "Lfixture/A;"}, model)
	if result.Status != "predicted" || result.ForwardPasses != 1 || len(result.ModelSHA256) != 64 || result.Abstained || result.PredictedClass != "color_argb" {
		t.Fatalf("expected model-backed color prediction, got %+v", result)
	}
	method := ParseMethod("Lfixture/A;", neuralColorCode)
	site, ok := NewSite(method, 0, nil)
	if !ok {
		t.Fatal("fixture constant not parsed")
	}
	expected := model.Graph.Predict(site.Graph(-1))[0]
	for i, p := range expected {
		if math.Abs(p-result.Probabilities[i]) > 1e-12 {
			t.Fatal("reported neural distribution was changed by rule or LR votes")
		}
	}
	array := strings.Replace(neuralColorCode, "invoke-virtual {p0, v0}, Landroid/widget/TextView;->setTextColor(I)V", "new-array v1, v0, [B", 1)
	other := AnalyzeNeural(Request{Code: array, Line: 3, Class: "Lfixture/A;"}, model)
	if other.Status != "predicted" || other.PredictedClass != "index_or_size" {
		t.Fatalf("changed consumer lost its model-backed role: %+v", other)
	}
	if other.Probabilities[labelIndex("color_argb")] == result.Probabilities[labelIndex("color_argb")] {
		t.Fatal("consumer change did not reach neural input")
	}
	mask := ".method public static a(I)I\n.registers 4\nconst/16 v0, 0x64\nand-int/2addr p0, v0\nreturn p0\n.end method"
	uncertain := AnalyzeNeural(Request{Code: mask, Line: 3, Class: "Lfixture/A;"}, model)
	if uncertain.Status != "predicted" || !uncertain.Abstained || uncertain.Reason != "neural_role_uncertain" {
		t.Fatalf("uncertain output was promoted: %+v", uncertain)
	}
}

func TestNeuralCoverageGatesDoNotInventPredictions(t *testing.T) {
	model, err := LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, code, reason string
		line               int
	}{
		{"overwritten", ".method static a()Z\n.registers 2\nconst/16 v0, 0x64\nconst/4 v0, 0x1\nreturn v0\n.end method", "no_retained_value_use", 3},
		{"dead", ".method static a(I)I\n.registers 2\ngoto :exit\nconst/16 v0, 0x64\nand-int/2addr p0, v0\n:exit\nreturn p0\n.end method", "unreachable_in_retained_normal_cfg", 4},
		{"float", ".method static a(Landroid/graphics/Paint;)V\n.registers 2\nconst v0, 0x3f800000\ninvoke-virtual {p0, v0}, Landroid/graphics/Paint;->setTextSize(F)V\nreturn-void\n.end method", "float_role_outside_taxonomy", 3},
		{"null argument", ".method static a()V\n.registers 1\nconst/4 v0, 0x0\ninvoke-static {v0}, Lfixture/A;->consume(Landroid/content/Context;)V\nreturn-void\n.end method", "reference_role_outside_taxonomy", 3},
		{"null argument after wide", ".method static a(J)V\n.registers 3\nconst/4 v0, 0x0\ninvoke-static/range {p0 .. p1}, Lfixture/A;->consume(J)V\ninvoke-static {p0, p1, v0}, Lfixture/A;->consume(JLjava/lang/Object;)V\nreturn-void\n.end method", "reference_role_outside_taxonomy", 3},
		{"null receiver", ".method static a()V\n.registers 1\nconst/4 v0, 0x0\ninvoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;\nreturn-void\n.end method", "reference_role_outside_taxonomy", 3},
		{"null return", ".method static a()Ljava/lang/Object;\n.registers 1\nconst/4 v0, 0x0\nreturn-object v0\n.end method", "reference_role_outside_taxonomy", 3},
		{"null object array value", ".method static a([Ljava/lang/Object;I)V\n.registers 3\nconst/4 v0, 0x0\naput-object v0, p0, p1\nreturn-void\n.end method", "reference_role_outside_taxonomy", 3},
		{"null object field value", ".method static a()V\n.registers 1\nconst/4 v0, 0x0\nsput-object v0, Lfixture/A;->item:Ljava/lang/Object;\nreturn-void\n.end method", "reference_role_outside_taxonomy", 3},
		{"bad signature", ".method static a([)V\nconst/4 v0, 0x1\nreturn v0\n.end method", "complete_single_method_required", 2},
		{"bad branch", ".method static a()I\nconst/4 v0, 0x1\ngoto :missing\nreturn v0\n.end method", "branch_target_missing", 2},
		{"bounded trace", ".method static a()I\n.registers 1\nconst/4 v0, 0x1\n" + strings.Repeat("nop\n", 4001) + "return v0\n.end method", "def_use_trace_limit", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := AnalyzeNeural(Request{Code: c.code, Line: c.line}, model)
			if result.Status != "skipped" || result.Reason != c.reason || result.ForwardPasses != 0 || len(result.Probabilities) != 0 {
				t.Fatalf("invalid coverage became neural output: %+v", result)
			}
		})
	}
	missing := AnalyzeNeural(Request{Code: neuralColorCode, Line: 3}, nil)
	if missing.Status != "unavailable" || missing.ForwardPasses != 0 {
		t.Fatal("missing GNN fell back to another scorer")
	}
	model.Graph.Classes[0], model.Graph.Classes[1] = model.Graph.Classes[1], model.Graph.Classes[0]
	wrong := AnalyzeNeural(Request{Code: neuralColorCode, Line: 3}, model)
	if wrong.Status != "unavailable" || wrong.ForwardPasses != 0 {
		t.Fatal("wrong class order accepted")
	}
}

func TestNeuralReferenceGateKeepsNumericObjectArrayIndex(t *testing.T) {
	model, err := LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Fatal(err)
	}
	code := ".method static a([Ljava/lang/Object;Ljava/lang/Object;)V\n.registers 3\nconst/4 v0, 0x0\naput-object p1, p0, v0\nreturn-void\n.end method"
	result := AnalyzeNeural(Request{Code: code, Line: 3}, model)
	if result.Status != "predicted" || result.ForwardPasses != 1 {
		t.Fatalf("numeric array index was mistaken for an object reference: %+v", result)
	}
}
