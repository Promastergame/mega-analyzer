package s1

import (
	"fmt"
	"strings"
)

// Task fixes the meaning of specialised decisions independently of display text.
const (
	TaskPatchEffect       = "patch_effect"
	TaskFalsePositive     = "false_positive"
	TaskServerDependency  = "server_dependency"
	TaskSeverity          = "severity"
	TaskLiteralRole       = "literal_role"
	TaskLiteralRoleNeural = "smali_literal_role_neural"
	TaskSkillRouting      = "skill_routing"
	TaskMath              = "math"
	TaskGame              = "game_move"
	TaskReasoning         = "reasoning"
	TaskSourceEvidence    = "source_evidence"
)

type NextCheck struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Why   string `json:"why"`
	Kind  string `json:"kind"`
}

// References identify evidence; clients resolve paths against their own scan.
type EvidenceReference struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	RunID  string `json:"run_id,omitempty"`
}

func validateTask(q Question) error {
	if q.Claim != nil {
		if q.Task != TaskReasoning || q.Type != TypeNoul {
			return fmt.Errorf("claim requires task=reasoning and type=noul")
		}
		for _, value := range []string{q.Claim.Subject, q.Claim.Predicate, q.Claim.Object, q.Claim.Time} {
			if len(value) > 512 || strings.HasPrefix(strings.TrimSpace(value), "$") {
				return fmt.Errorf("claim requires bounded, concrete values")
			}
		}
		if strings.TrimSpace(q.Claim.Subject) == "" || strings.TrimSpace(q.Claim.Predicate) == "" {
			return fmt.Errorf("claim requires subject and predicate")
		}
	}
	if q.Polarity != "" && q.Polarity != "positive" && q.Polarity != "negative" {
		return fmt.Errorf("polarity must be positive or negative")
	}
	if q.Polarity != "" && q.Type != TypeNoul {
		return fmt.Errorf("polarity is only valid for noul")
	}
	if q.AbstainKey != "" && q.Type != TypeChoice {
		return fmt.Errorf("abstain_key is only valid for choice")
	}
	switch q.Task {
	case "":
	case TaskMath:
	case TaskGame:
		if q.Type != TypeChoice {
			return fmt.Errorf("game_move requires choice")
		}
	case TaskReasoning:
		if q.Type != TypeNoul && q.Type != TypeChoice {
			return fmt.Errorf("reasoning requires noul or choice")
		}
	case TaskPatchEffect, TaskFalsePositive:
		if q.Type != TypeNoul {
			return fmt.Errorf("task %s requires noul", q.Task)
		}
	case TaskServerDependency:
		if q.Type != TypeNoul && q.Type != TypeScore {
			return fmt.Errorf("server_dependency requires noul or score")
		}
	case TaskSeverity:
		if q.Type != TypeScore {
			return fmt.Errorf("severity requires score")
		}
	case TaskSkillRouting:
		if q.Type != TypeChoice {
			return fmt.Errorf("skill_routing requires choice")
		}
	case TaskLiteralRole:
		if q.Type != TypeChoice {
			return fmt.Errorf("literal_role requires choice")
		}
	case TaskLiteralRoleNeural:
		if q.Type != TypeChoice || q.AbstainKey != "unknown" {
			return fmt.Errorf("smali_literal_role_neural requires choice and abstain_key=unknown")
		}
	case TaskSourceEvidence:
		if q.Type != TypeChoice {
			return fmt.Errorf("source_evidence requires choice")
		}
	default:
		return fmt.Errorf("unknown task %q", q.Task)
	}
	return nil
}
