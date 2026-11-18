package gnn

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// validWeightJSON builds a minimal but structurally complete weight file: one
// layer 36→8 (architecture, weights, bias), 8-class classifier head, correct
// taxonomy stamp.
func validWeightJSON(t *testing.T) []byte {
	t.Helper()
	const (
		inDim  = ExpectedFeatureDim
		outDim = NumVulnClasses
	)
	weights := make([]float64, inDim*outDim)
	for i := range weights {
		weights[i] = 0.001
	}
	bias := make([]float64, outDim)
	classifierW := make([]float64, 2*outDim*NumVulnClasses)
	classifierB := make([]float64, NumVulnClasses)
	classNames := make([]string, NumVulnClasses)
	for i := range classNames {
		classNames[i] = VulnClassName(VulnClass(i))
	}
	wf := map[string]any{
		"format_version": 2,
		"config": map[string]any{
			"layers": []map[string]any{{
				"features_in": inDim, "features_out": outDim,
				"activation": "ReLU", "dropout": 0.0,
			}},
			"num_classes":   NumVulnClasses,
			"readout":       "meanmax",
			"normalization": "symmetric",
			"residual":      false,
		},
		"layer_data": []map[string]any{{
			"weights": weights, "bias": bias,
			"norm_gamma": make([]float64, outDim), "norm_beta": make([]float64, outDim),
		}},
		"classifier_weights": classifierW,
		"classifier_bias":    classifierB,
		"metadata": map[string]any{
			"version":                "gnn-trained-v2",
			"train_samples":          120,
			"val_accuracy":           0.91,
			"class_names":            classNames,
			"feature_schema_version": MaxSupportedFeatureSchemaVersion,
			"conformal_q90":          0.21,
			"ood_threshold":          0.85,
		},
	}
	data, err := json.Marshal(wf)
	if err != nil {
		t.Fatalf("marshal weight file: %v", err)
	}
	return data
}

func TestValidateRejectsNativeOverflowAndInvalidNormalization(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"classifier_overflow", func(w map[string]any) { w["classifier_bias"].([]any)[0] = math.MaxFloat64 }},
		{"layer_bias_overflow", func(w map[string]any) { w["layer_data"].([]any)[0].(map[string]any)["bias"].([]any)[0] = 1e100 }},
		{"unpaired_norm", func(w map[string]any) { delete(w["layer_data"].([]any)[0].(map[string]any), "norm_beta") }},
		{"negative_dimension", func(w map[string]any) {
			w["config"].(map[string]any)["layers"].([]any)[0].(map[string]any)["features_out"] = -1
		}},
		{"invalid_calibration", func(w map[string]any) { w["metadata"].(map[string]any)["conformal_q90"] = 1.5 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wf map[string]any
			if err := json.Unmarshal(validWeightJSON(t), &wf); err != nil {
				t.Fatal(err)
			}
			test.edit(wf)
			data, err := json.Marshal(wf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateModelFile(writeTemp(t, data)); err == nil {
				t.Fatal("invalid native model parameters accepted")
			}
		})
	}
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "weights.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateModelFileAcceptsCompatibleFile(t *testing.T) {
	meta, err := ValidateModelFile(writeTemp(t, validWeightJSON(t)))
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if meta.TrainerVersion != "gnn-trained-v2" {
		t.Errorf("trainer version = %q", meta.TrainerVersion)
	}
	if meta.TrainSamples != 120 || meta.ValAccuracy != 0.91 {
		t.Errorf("provenance lost: %+v", meta)
	}
	if !meta.HasCalibration || meta.ConformalQ90 != 0.21 {
		t.Errorf("calibration metadata lost: %+v", meta)
	}
	if meta.OODThreshold != 0.85 {
		t.Errorf("OOD threshold lost: %+v", meta)
	}
}

func TestValidateModelFileReadoutMatrixShape(t *testing.T) {
	for _, readout := range []string{"mean", "max", "meanmax"} {
		t.Run(readout, func(t *testing.T) {
			var wf map[string]any
			if err := json.Unmarshal(validWeightJSON(t), &wf); err != nil {
				t.Fatal(err)
			}
			wf["config"].(map[string]any)["readout"] = readout
			multiplier := 1
			if readout == "meanmax" {
				multiplier = 2
			}
			wf["classifier_weights"] = make([]float64, multiplier*NumVulnClasses*NumVulnClasses)
			data, err := json.Marshal(wf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateModelFile(writeTemp(t, data)); err != nil {
				t.Fatalf("native-compatible %s matrix rejected: %v", readout, err)
			}
			wf["classifier_weights"] = make([]float64, NumVulnClasses)
			data, err = json.Marshal(wf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateModelFile(writeTemp(t, data)); err == nil {
				t.Fatal("scalar-per-class weights accepted for a wider graph embedding")
			}
		})
	}
}

func TestValidateModelFileRejectsIncompatible(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(wf map[string]any)
	}{
		{"feature dim mismatch", func(wf map[string]any) {
			wf["config"].(map[string]any)["layers"] = []map[string]any{{
				"features_in": 27, "features_out": 8, "activation": "ReLU", "dropout": 0.0,
			}}
		}},
		{"wrong class count", func(wf map[string]any) {
			wf["config"].(map[string]any)["num_classes"] = 5
		}},
		{"taxonomy drift", func(wf map[string]any) {
			names := make([]string, NumVulnClasses)
			for i := range names {
				names[i] = VulnClassName(VulnClass(i))
			}
			names[2] = "money-maker" // wrong name at a fixed ABI index
			wf["metadata"].(map[string]any)["class_names"] = names
		}},
		{"missing taxonomy", func(wf map[string]any) {
			wf["metadata"].(map[string]any)["class_names"] = []string{}
		}},
		{"newer feature schema", func(wf map[string]any) {
			wf["metadata"].(map[string]any)["feature_schema_version"] = MaxSupportedFeatureSchemaVersion + 1
		}},
		{"classifier shape", func(wf map[string]any) {
			wf["classifier_weights"] = make([]float64, 3)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var wf map[string]any
			if err := json.Unmarshal(validWeightJSON(t), &wf); err != nil {
				t.Fatal(err)
			}
			tc.mutate(wf)
			data, err := json.Marshal(wf)
			if err != nil {
				t.Fatal(err)
			}
			if _, verr := ValidateModelFile(writeTemp(t, data)); verr == nil {
				t.Errorf("%s: expected rejection, got nil", tc.name)
			}
		})
	}
}

func TestValidateModelFileRejectsDummySentinel(t *testing.T) {
	if _, err := ValidateModelFile("__dummy__"); err == nil {
		t.Error("dummy sentinel must not validate as a file")
	}
	if _, err := ValidateModelFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file must be rejected")
	}
}
