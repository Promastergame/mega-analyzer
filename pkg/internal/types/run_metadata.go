package types

// RunMetadata describes the core scan without recording command-line secrets,
// tokens, local cache paths or external service credentials.
type RunMetadata struct {
	ID             string            `json:"id,omitempty"`
	ArtifactSHA256 string            `json:"artifact_sha256,omitempty"`
	Identity       map[string]string `json:"identity,omitempty"`
	Status         string            `json:"status"`
	StopReason     string            `json:"stop_reason,omitempty"`
	Limitations    []string          `json:"limitations,omitempty"`
	Profile        string            `json:"profile"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	CoreSettings   map[string]any    `json:"core_settings"`
}
