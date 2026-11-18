package gnn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
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
	Weights   []float64 `json:"weights"`
	Bias      []float64 `json:"bias"`
	NormGamma []float64 `json:"norm_gamma"`
	NormBeta  []float64 `json:"norm_beta"`
}

// weightFile is the subset of the Rust `WeightStore` JSON that the Go side
// verifies before handing the file to the native runtime. Unknown fields are
// ignored on purpose: the Rust side owns the full schema.
type weightFile struct {
	FormatVersion int `json:"format_version"`
	Config        struct {
		Layers     []layerCfgJSON `json:"layers"`
		NumClasses int            `json:"num_classes"`
		Readout    string         `json:"readout"`
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
	SHA256               string
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
	if strings.EqualFold(filepath.Ext(path), ".gnnbuf") {
		return nil, errors.New("gnn validate: compact .gnnbuf is not supported by the Go validation contract; export gnn_weights.json")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gnn validate: read weight file: %w", err)
	}
	defer f.Close()
	const maxWeightBytes = 64 << 20
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxWeightBytes {
		return nil, errors.New("gnn validate: weights must be a regular file of at most 64 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxWeightBytes+1))
	if err != nil || len(data) > maxWeightBytes {
		return nil, errors.New("gnn validate: weight file exceeds read budget")
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
	// The native head is a class-by-embedding matrix. MeanMax concatenates
	// the mean and maximum embeddings, doubling the final layer's width.
	readoutMultiplier := 1
	switch wf.Config.Readout {
	case "", "mean", "max":
	case "meanmax":
		readoutMultiplier = 2
	default:
		return nil, fmt.Errorf("gnn validate: unsupported readout %q", wf.Config.Readout)
	}
	lastWidth := wf.Config.Layers[len(wf.Config.Layers)-1].FeaturesOut
	maxInt := int(^uint(0) >> 1)
	if lastWidth <= 0 || lastWidth > maxInt/(readoutMultiplier*NumVulnClasses) {
		return nil, fmt.Errorf("gnn validate: invalid final layer width %d", lastWidth)
	}
	classifierSize := lastWidth * readoutMultiplier * NumVulnClasses
	if len(wf.ClassifierWeights) != classifierSize || len(wf.ClassifierBias) != NumVulnClasses {
		return nil, fmt.Errorf("gnn validate: classifier shape mismatch: weights=%d bias=%d, want %d weights and %d biases", len(wf.ClassifierWeights), len(wf.ClassifierBias), classifierSize, NumVulnClasses)
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
		if layer.FeaturesIn <= 0 || layer.FeaturesOut <= 0 || layer.FeaturesIn > maxInt/layer.FeaturesOut {
			return nil, fmt.Errorf("gnn validate: layer %d has invalid or overflowing dimensions", i)
		}
		if i > 0 && layer.FeaturesIn != wf.Config.Layers[i-1].FeaturesOut {
			return nil, fmt.Errorf("gnn validate: layer %d input differs from previous output", i)
		}
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
		if (lw.NormGamma == nil) != (lw.NormBeta == nil) ||
			(lw.NormGamma != nil && (len(lw.NormGamma) != layer.FeaturesOut || len(lw.NormBeta) != layer.FeaturesOut)) {
			return nil, fmt.Errorf("gnn validate: layer %d has invalid normalization vectors", i)
		}
		for _, values := range [][]float64{lw.Weights, lw.Bias, lw.NormGamma, lw.NormBeta} {
			if !finiteNativeWeights(values) {
				return nil, fmt.Errorf("gnn validate: layer %d contains non-finite or out-of-range parameters", i)
			}
		}
	}
	if !finiteNativeWeights(wf.ClassifierWeights) || !finiteNativeWeights(wf.ClassifierBias) {
		return nil, errors.New("gnn validate: classifier contains non-finite or out-of-range parameters")
	}
	if math.IsNaN(wf.Metadata.ValAccuracy) || math.IsInf(wf.Metadata.ValAccuracy, 0) || wf.Metadata.ValAccuracy < 0 || wf.Metadata.ValAccuracy > 1 {
		return nil, errors.New("gnn validate: validation accuracy must be in 0..1")
	}
	for _, value := range []*float64{wf.Metadata.ConformalQ90, wf.Metadata.OODThreshold} {
		if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1) {
			if value == wf.Metadata.ConformalQ90 || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 {
				return nil, errors.New("gnn validate: invalid calibration metadata")
			}
		}
	}
	digest := sha256.Sum256(data)

	meta := &ModelMetadata{
		SHA256:               hex.EncodeToString(digest[:]),
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

func finiteNativeWeights(values []float64) bool {
	for _, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > math.MaxFloat32 {
			return false
		}
	}
	return true
}
