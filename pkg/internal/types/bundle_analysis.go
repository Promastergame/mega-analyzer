package types

// Bundle counters are separate from the DEX/Smali pipeline: no fabricated
// application classes or inferred risk verdict from a zero-file core scan.
type BundleAnalysisSummary struct {
	Standalone      bool    `json:"standalone"`
	Status          string  `json:"status"`
	Files           int     `json:"files"`
	StringsTotal    int     `json:"strings_total"`
	StringsScanned  int     `json:"strings_scanned"`
	Observations    int     `json:"observations"`
	RiskSignals     int     `json:"risk_signals"`
	ScanSeconds     float64 `json:"scan_seconds"`
	ElapsedSeconds  float64 `json:"elapsed_seconds"`
	PipelineSeconds float64 `json:"pipeline_seconds"`
	Verdict         string  `json:"verdict"`
}

type HermesExportCoverage struct {
	TotalFunctions       int    `json:"total_functions"`
	ScannedFunctions     int    `json:"scanned_functions"`
	DecodedFunctions     int    `json:"decoded_functions"`
	FailedFunctions      int    `json:"failed_functions"`
	SkippedFunctions     int    `json:"skipped_functions"`
	TotalBytecodeBytes   uint64 `json:"total_bytecode_bytes"`
	DecodedBytecodeBytes uint64 `json:"decoded_bytecode_bytes"`
	Instructions         uint64 `json:"instructions"`
	OutputBytes          int64  `json:"output_bytes"`
	FunctionLimit        int    `json:"function_limit"`
	BytecodeLimit        uint64 `json:"bytecode_limit"`
	InstructionLimit     uint64 `json:"instruction_limit"`
	OutputLimit          int64  `json:"output_limit"`
	LimitReason          string `json:"limit_reason,omitempty"`
}

type StaticOutputStage struct {
	Stage            string                `json:"stage"`
	Status           string                `json:"status"`
	Path             string                `json:"path,omitempty"`
	Diagnostics      []string              `json:"diagnostics,omitempty"`
	Export           *HermesExportCoverage `json:"export,omitempty"`
	TotalFunctions   int                   `json:"total_functions,omitempty"`
	DecodedFunctions int                   `json:"decoded_functions,omitempty"`
	TotalCalls       int                   `json:"total_calls,omitempty"`
	RecordedCalls    int                   `json:"recorded_calls,omitempty"`
}
