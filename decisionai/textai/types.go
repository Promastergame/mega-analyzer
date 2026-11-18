// Package textai is a CPU-only task-specific text classifier, not an LLM or a verifier.
package textai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

const Version = "0.3.0"
const LegacyVersion = "0.2.0"

// Dims is the hashed feature count of v0.2 models. New models use an exact vocabulary.
const Dims = 2048
const Task = "patch_effect_confirmation"

type Checks struct {
	AppOwned         bool   `json:"app_owned"`
	Library          bool   `json:"library"`
	Scope            string `json:"scope"`
	Build            string `json:"build"`
	Runtime          string `json:"runtime"`
	EffectVerified   bool   `json:"effect_verified"`
	ServerDependency string `json:"server_dependency"`
	TestedSHA256     string `json:"tested_sha256"`
}
type Request struct {
	ID            string   `json:"id"`
	TaskID        string   `json:"task_id"`
	State         string   `json:"state"`
	Question      string   `json:"question"`
	TrueWhen      string   `json:"true_when"`
	FalseWhen     string   `json:"false_when"`
	Threshold     *float64 `json:"threshold,omitempty"`
	CandidateCode string   `json:"candidate_code,omitempty"`
	Checks        *Checks  `json:"checks,omitempty"`
}
type Contribution struct {
	Feature      string  `json:"feature"`
	Contribution float64 `json:"contribution"`
}
type Prediction struct {
	Value             float64         `json:"value"`
	Kind              string          `json:"kind"`
	Coverage          float64         `json:"vocabulary_coverage"`
	Support           float64         `json:"lexical_support"`
	Fields            []FieldCoverage `json:"fields,omitempty"`
	Entropy           float64         `json:"entropy"`
	Logit             float64         `json:"logit"`
	Intercept         float64         `json:"intercept_logit"`
	OtherContribution float64         `json:"other_contribution"`
	Contributions     []Contribution  `json:"contributions"`
	Notes             []string        `json:"notes"`
}

// FieldCoverage separates exact word coverage from partial subword support.
type FieldCoverage struct {
	Field     string   `json:"field"`
	Tokens    int      `json:"tokens"`
	Known     int      `json:"known_tokens"`
	Coverage  float64  `json:"vocabulary_coverage"`
	Subwords  float64  `json:"subword_coverage"`
	Support   float64  `json:"lexical_support"`
	Unknown   []string `json:"unknown_words,omitempty"`
	Truncated bool     `json:"truncated"`
}
type Gate struct {
	Status          string   `json:"status"`
	Reasons         []string `json:"reasons"`
	CandidateSHA256 string   `json:"candidate_sha256,omitempty"`
	ChecksSource    string   `json:"checks_source"`
}
type Report struct {
	Version            string        `json:"version"`
	ID                 string        `json:"id"`
	TaskID             string        `json:"task_id"`
	Answer             string        `json:"answer"`
	Prediction         Prediction    `json:"prediction"`
	Threshold          float64       `json:"threshold"`
	EffectiveThreshold float64       `json:"effective_threshold"`
	AboveThreshold     bool          `json:"above_threshold"`
	Gate               Gate          `json:"gate"`
	Decision           string        `json:"decision"`
	CanApply           bool          `json:"can_apply"`
	Explanation        string        `json:"explanation"`
	Warnings           []string      `json:"warnings"`
	AbstentionReasons  []string      `json:"abstention_reasons"`
	Model              *ModelSummary `json:"model,omitempty"`
	// Semantic holds a fallback answer from the meaning engine (semai). It is
	// filled only by the CLI/HTTP layer when the lexical model abstains; the
	// lexical Predict/Train/Evaluate path never touches it. Kept as any to
	// avoid coupling the lexical core to the semantic package.
	Semantic any `json:"semantic,omitempty"`
	// Facts is a deterministic answer from explicit facts in state/question (e.g. "7 монет < цена 10"),
	// filled by the caller when the question is not about patch confirmation. It never changes Decision/gate.
	Facts *FactsAnswer `json:"facts,omitempty"`
}

type FactsAnswer struct {
	Answer     string   `json:"answer"`
	Who        []string `json:"who,omitempty"`
	Confidence float64  `json:"confidence"`
	Reasoning  []string `json:"reasoning"`
	Solver     string   `json:"solver"`
	// Steps/Total: per-step effects and the summed change from the events solver (any = semai types).
	Steps any `json:"steps,omitempty"`
	Total any `json:"total,omitempty"`
}

type ModelSummary struct {
	Version       string  `json:"version"`
	FeatureSchema string  `json:"feature_schema"`
	Features      int     `json:"features"`
	Synthetic     bool    `json:"synthetic"`
	Metrics       Metrics `json:"metrics"`
}

func finite(v float64) bool  { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func SHA256(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func Validate(r Request) error {
	if r.TaskID != Task {
		return fmt.Errorf("supported task_id: %s (other tasks require a new trained classifier)", Task)
	}
	for k, v := range map[string]string{"state": r.State, "question": r.Question, "true_when": r.TrueWhen, "false_when": r.FalseWhen} {
		if strings.TrimSpace(v) == "" || len(v) > 32768 {
			return fmt.Errorf("%s must contain 1..32768 bytes", k)
		}
	}
	if len(r.CandidateCode) > 1048576 || len(r.ID) > 256 {
		return fmt.Errorf("candidate/id too long")
	}
	if r.Threshold != nil && (!finite(*r.Threshold) || *r.Threshold < 0 || *r.Threshold > 1) {
		return fmt.Errorf("threshold must be in [0,1]")
	}
	if c := r.Checks; c != nil {
		for _, v := range []string{c.Build, c.Runtime} {
			switch v {
			case "", "not_run", "pass", "fail":
			default:
				return fmt.Errorf("build/runtime must be not_run, pass or fail")
			}
		}
		switch c.Scope {
		case "", "audit", "defensive", "test_fixture":
		default:
			return fmt.Errorf("invalid checks scope")
		}
		switch c.ServerDependency {
		case "", "unknown", "local_only", "online":
		default:
			return fmt.Errorf("invalid server_dependency")
		}
		if c.TestedSHA256 != "" {
			b, e := hex.DecodeString(c.TestedSHA256)
			if e != nil || len(b) != 32 {
				return fmt.Errorf("tested_sha256 must be 64 hex characters")
			}
		}
	}
	return nil
}
