package gnn

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
)

// ExpectedFeatureDim is the per-node feature width the Go graph builder
// produces (pkg/internal/gnngraph.FeatureDim) and the Rust feature extractor
// emits (NodeFeatures::DIMS). A weight file trained against a different
// schema would still run — every layer happily consumes whatever width the
// config declares — and silently return garbage, so it is rejected up front.
const ExpectedFeatureDim = 36

// MaxSupportedFeatureSchemaVersion is the newest feature_schema_version stamp
// this build understands. Larger values mean the file was produced by a newer
// trainer whose features may not match this runtime's graph builder.
const MaxSupportedFeatureSchemaVersion = 1

// layerCfgJSON is one entry of the weight file's architecture declaration.
type layerCfgJSON struct {
	FeaturesIn  int `json:"features_in"`
	FeaturesOut int `json:"features_out"`
}

// layerWeightsJSON is one entry of the weight file's parameter store.
type layerWeightsJSON struct {
	Weights []float64 `json:"weights"`
	Bias    []float64 `json:"bias"`
}

// weightFile is the subset of the Rust `WeightStore` JSON that the Go side
// verifies before handing the file to the native runtime. Unknown fields are
// ignored on purpose: the Rust side owns the full schema.
type weightFile struct {
	FormatVersion int `json:"format_version"`
	Config        struct {
		Layers     []layerCfgJSON `json:"layers"`
		NumClasses int            `json:"num_classes"`
	} `json:"config"`
	LayerData         []layerWeightsJSON `json:"layer_data"`
	ClassifierWeights []float64          `json:"classifier_weights"`
	ClassifierBias    []float64          `json:"classifier_bias"`
	Metadata          struct {
		Version              string   `json:"version"`
		ClassNames           []string `json:"class_names"`
		FeatureSchemaVersion int      `json:"feature_schema_version"`
		TrainSamples         int      `json:"train_samples"`
		ValAccuracy          float64  `json:"val_accuracy"`
		ConformalQ90         *float64 `json:"conformal_q90"`
		OODThreshold         *float64 `json:"ood_threshold"`
	} `json:"metadata"`
}

// ModelMetadata is the validated, caller-visible view of a weight file's
// provenance. The calibration fields are surfaced so runners can report
// whether the model carries calibration metadata without a second read.
type ModelMetadata struct {
	TrainerVersion       string
	ClassNames           []string
	FeatureSchemaVersion int
	TrainSamples         int
	ValAccuracy          float64
	HasCalibration       bool
	ConformalQ90         float64
	OODThreshold         float64
}

// ValidateModelFile verifies a GNN weight file against the inference
// contract *before* the native runtime loads it:
//
//   - weight format version is one this runtime understands;
//   - the first layer's input width equals ExpectedFeatureDim;
//   - declared class count, classifier shape and the taxonomy class names
//     match the classes VulnClassName maps FFI indices with;
//   - per-layer weight/bias lengths match the declared architecture;
//   - the feature_schema_version stamp is not from a newer runtime.
//
// Incompatible files are rejected here, at load time, instead of being
// trusted to produce meaningful probabilities at inference time.
func ValidateModelFile(path string) (*ModelMetadata, error) {
	if path == "" || path == "__dummy__" {
		return nil, errors.New("gnn validate: no weight file to validate (dummy model requested)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gnn validate: read weight file: %w", err)
	}
	var wf weightFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("gnn validate: not a parseable weight file: %w", err)
	}

	if wf.FormatVersion < 1 || wf.FormatVersion > 2 {
		return nil, fmt.Errorf("gnn validate: unsupported weight format version %d (supported: 1..2)", wf.FormatVersion)
	}
	if len(wf.Config.Layers) == 0 {
		return nil, errors.New("gnn validate: weight file declares no layers")
	}
	if got := wf.Config.Layers[0].FeaturesIn; got != ExpectedFeatureDim {
		return nil, fmt.Errorf("gnn validate: model expects %d-dim node features but this runtime builds %d-dim graphs — retrain or update the runtime", got, ExpectedFeatureDim)
	}
	if wf.Config.NumClasses != NumVulnClasses {
		return nil, fmt.Errorf("gnn validate: model declares %d classes, runtime maps %d", wf.Config.NumClasses, NumVulnClasses)
	}
	if len(wf.ClassifierWeights) != NumVulnClasses || len(wf.ClassifierBias) != NumVulnClasses {
		return nil, fmt.Errorf("gnn validate: classifier shape mismatch: weights=%d bias=%d, want %d each", len(wf.ClassifierWeights), len(wf.ClassifierBias), NumVulnClasses)
	}

	// Taxonomy: the class index order is an ABI contract between the Rust
	// engine and VulnClassName. A file trained against a different class
	// order would map every prediction to the wrong label.
	if len(wf.Metadata.ClassNames) == 0 {
		return nil, errors.New("gnn validate: weight file lacks taxonomy metadata (class_names) — re-export it with the current trainer")
	}
	if len(wf.Metadata.ClassNames) != NumVulnClasses {
		return nil, fmt.Errorf("gnn validate: taxonomy has %d names, runtime maps %d classes", len(wf.Metadata.ClassNames), NumVulnClasses)
	}
	for i, name := range wf.Metadata.ClassNames {
		if name != VulnClassName(VulnClass(i)) {
			return nil, fmt.Errorf("gnn validate: taxonomy mismatch at class %d: file has %q, runtime expects %q", i, name, VulnClassName(VulnClass(i)))
		}
	}

	if wf.Metadata.FeatureSchemaVersion > MaxSupportedFeatureSchemaVersion {
		return nil, fmt.Errorf("gnn validate: weight file feature schema v%d is newer than the runtime's v%d — update the analyzer or retrain",
			wf.Metadata.FeatureSchemaVersion, MaxSupportedFeatureSchemaVersion)
	}

	for i, layer := range wf.Config.Layers {
		if i >= len(wf.LayerData) {
			return nil, fmt.Errorf("gnn validate: layer %d has no weight data", i)
		}
		lw := wf.LayerData[i]
		if len(lw.Weights) != layer.FeaturesIn*layer.FeaturesOut {
			return nil, fmt.Errorf("gnn validate: layer %d has %d weights, architecture declares %d",
				i, len(lw.Weights), layer.FeaturesIn*layer.FeaturesOut)
		}
		if len(lw.Bias) != layer.FeaturesOut {
			return nil, fmt.Errorf("gnn validate: layer %d has %d bias values, architecture declares %d", i, len(lw.Bias), layer.FeaturesOut)
		}
		for _, v := range lw.Weights {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("gnn validate: layer %d contains non-finite weights", i)
			}
		}
	}

	meta := &ModelMetadata{
		TrainerVersion:       wf.Metadata.Version,
		ClassNames:           append([]string(nil), wf.Metadata.ClassNames...),
		FeatureSchemaVersion: wf.Metadata.FeatureSchemaVersion,
		TrainSamples:         wf.Metadata.TrainSamples,
		ValAccuracy:          wf.Metadata.ValAccuracy,
	}
	if wf.Metadata.ConformalQ90 != nil && !math.IsNaN(*wf.Metadata.ConformalQ90) {
		meta.HasCalibration = true
		meta.ConformalQ90 = *wf.Metadata.ConformalQ90
	}
	if wf.Metadata.OODThreshold != nil && !math.IsNaN(*wf.Metadata.OODThreshold) {
		meta.OODThreshold = *wf.Metadata.OODThreshold
	}
	return meta, nil
}
