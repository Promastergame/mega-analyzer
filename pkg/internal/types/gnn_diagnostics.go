package types

// GNNDiagnostics describes model coverage separately from accepted findings.
// The licensing/protection taxonomy is not a malware-family safety vote.
type GNNDiagnostics struct {
	SchemaVersion             int                   `json:"schema_version"`
	Status                    string                `json:"status"`
	StaticOnly                bool                  `json:"static_only"`
	Scope                     string                `json:"scope"`
	Reason                    string                `json:"reason,omitempty"`
	Error                     string                `json:"error,omitempty"`
	Model                     GNNModelInfo          `json:"model"`
	MethodsDiscovered         int                   `json:"methods_discovered"`
	MethodsScheduled          int                   `json:"methods_scheduled"`
	MethodsProcessed          int                   `json:"methods_processed"`
	MethodsInferred           int                   `json:"methods_inferred"`
	MethodsSkipped            int                   `json:"methods_skipped"`
	MethodsFailed             int                   `json:"methods_failed"`
	MethodsNotProcessed       int                   `json:"methods_not_processed"`
	PredictionsByClass        map[string]int        `json:"predictions_by_class"`
	AcceptedFindings          int                   `json:"accepted_findings"`
	UncertainPredictions      int                   `json:"uncertain_predictions"`
	LibrarySuppressed         int                   `json:"library_suppressed"`
	UncorroboratedPredictions int                   `json:"uncorroborated_predictions"`
	Cancelled                 bool                  `json:"cancelled"`
	DiagnosticsOmitted        int                   `json:"diagnostics_omitted"`
	Methods                   []GNNMethodDiagnostic `json:"methods"`
}

type GNNModelInfo struct {
	Path                   string   `json:"path,omitempty"`
	SHA256                 string   `json:"sha256,omitempty"`
	Format                 string   `json:"format,omitempty"`
	TrainerVersion         string   `json:"trainer_version,omitempty"`
	Taxonomy               []string `json:"taxonomy"`
	FeatureSchema          string   `json:"feature_schema,omitempty"`
	FeatureDim             int      `json:"feature_dim"`
	TrainSamples           int      `json:"train_samples"`
	ValidationAccuracy     float64  `json:"validation_accuracy"`
	HasCalibrationMetadata bool     `json:"has_calibration_metadata"`
	Dummy                  bool     `json:"dummy"`
}

type GNNMethodDiagnostic struct {
	File               string             `json:"file"`
	Method             string             `json:"method"`
	Status             string             `json:"status"`
	Reason             string             `json:"reason,omitempty"`
	GraphKind          string             `json:"graph_kind,omitempty"`
	Nodes              uint64             `json:"nodes,omitempty"`
	PredictedClass     string             `json:"predicted_class,omitempty"`
	Confidence         float32            `json:"confidence,omitempty"`
	Margin             float32            `json:"margin,omitempty"`
	NormalizedEntropy  float32            `json:"normalized_entropy,omitempty"`
	PassesQualityGate  bool               `json:"passes_quality_gate"`
	Outcome            string             `json:"outcome,omitempty"`
	ClassProbabilities map[string]float32 `json:"class_probabilities,omitempty"`
}
