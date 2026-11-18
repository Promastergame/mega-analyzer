// Package engine implements a bounded, explainable decision layer. It never executes input code.
package engine

const Version = "0.3.0"

var FeatureNames = []string{"instructions", "invokes", "branches", "constants", "returns", "register_budget", "evidence_count", "app_owned", "library", "server_dependency", "patch_requested", "patch_delta_ratio", "patch_replacement_scale", "patch_preflight_ok", "patch_widened_opcode"}

type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value,omitempty"`
}
type Question struct {
	Text      string      `json:"question"`
	TrueWhen  []Condition `json:"true_when"`
	FalseWhen []Condition `json:"false_when"`
}
type Thresholds struct {
	Finding float64 `json:"finding"`
	Patch   float64 `json:"patch"`
}

func DefaultThresholds() Thresholds { return Thresholds{0.65, 0.85} }

type Meta struct {
	AppOwned         bool     `json:"app_owned"`
	Library          bool     `json:"library"`
	ServerDependency bool     `json:"server_dependency"`
	Evidence         []string `json:"evidence"`
}
type PatchRequest struct {
	Line        int    `json:"line"`
	Expected    int64  `json:"expected"`
	Replacement int64  `json:"replacement"`
	Target      string `json:"target,omitempty"`
}
type Request struct {
	ID        string         `json:"id"`
	Code      string         `json:"code"`
	State     map[string]any `json:"state"`
	Questions []Question     `json:"questions,omitempty"`
	Threshold *Thresholds    `json:"threshold,omitempty"`
	Meta      Meta           `json:"meta"`
	Scope     string         `json:"scope"`
	Patch     *PatchRequest  `json:"patch,omitempty"`
}
type Answer struct {
	Question string   `json:"question"`
	State    string   `json:"state"`
	Reasons  []string `json:"reasons"`
}
type Check struct {
	Status string   `json:"status"`
	Issues []string `json:"issues"`
}
type Assessment struct {
	Value          float64            `json:"value"`
	Kind           string             `json:"kind"`
	Target         string             `json:"target"`
	AboveThreshold bool               `json:"above_threshold"`
	Contributions  map[string]float64 `json:"contributions"`
	Notes          []string           `json:"notes"`
}
type PatchPlan struct {
	Original     string   `json:"original_code"`
	Patched      string   `json:"patched_code"`
	OriginalHash string   `json:"original_sha256"`
	PatchedHash  string   `json:"patched_sha256"`
	Diff         string   `json:"diff"`
	Before       int64    `json:"before"`
	After        int64    `json:"after"`
	Delta        int64    `json:"delta"`
	Percent      *float64 `json:"percent,omitempty"`
	Explanation  string   `json:"explanation"`
	Validation   Check    `json:"validation"`
	Build        string   `json:"build"`
	Runtime      string   `json:"runtime"`
	CanApply     bool     `json:"can_apply"`
}
type Report struct {
	Version         string             `json:"version"`
	ID              string             `json:"id"`
	Features        map[string]float64 `json:"features"`
	Answers         []Answer           `json:"answers"`
	Validation      Check              `json:"validation"`
	Finding         Assessment         `json:"finding"`
	PatchAssessment Assessment         `json:"patch_assessment"`
	Decision        string             `json:"decision"`
	Reasons         []string           `json:"reasons"`
	Plan            *PatchPlan         `json:"plan,omitempty"`
	Advice          *PatchAdvice       `json:"advice,omitempty"`
}

// Decode rejects unknown input keys and trailing values (including accidentally concatenated JSON).
func Decode(data []byte, dst any) error { return decodeStrict(data, dst) }
