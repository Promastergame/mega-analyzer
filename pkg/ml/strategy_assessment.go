package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// MethodRole describes the semantic role of a method. It prevents a generic
// method name such as show/load/init from being treated as a decision point.
type MethodRole string

const (
	MethodRoleUnknown       MethodRole = "unknown"
	MethodRoleBooleanGate   MethodRole = "boolean_gate"
	MethodRoleValueProvider MethodRole = "value_provider"
	MethodRoleCallback      MethodRole = "callback"
	MethodRoleInitializer   MethodRole = "initializer"
	MethodRoleWrapper       MethodRole = "wrapper"
)

// StrategyMetadata makes strategy selection explainable and reviewable.
type StrategyMetadata struct {
	ID                   string       `json:"id"`
	SupportedRoles       []MethodRole `json:"supported_roles,omitempty"`
	SupportedReturns     []string     `json:"supported_returns,omitempty"`
	PreservesControlFlow bool         `json:"preserves_control_flow"`
	RequiresCFG          bool         `json:"requires_cfg"`
	RequiresDFG          bool         `json:"requires_dfg"`
	HighRisk             bool         `json:"high_risk"`
}

type StrategyAssessment struct {
	Applicable bool     `json:"applicable"`
	Score      float64  `json:"score"`
	Reasons    []string `json:"reasons,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// StrategyDescriber is optional to preserve compatibility with third-party
// strategies implementing the original PatchStrategy interface.
type StrategyDescriber interface {
	Metadata() StrategyMetadata
}

func assessStrategy(strategy PatchStrategy, mi *shared.MethodInfo, mode PatchMode) StrategyAssessment {
	a := StrategyAssessment{}
	if strategy == nil || mi == nil {
		a.Reasons = []string{"missing_strategy_or_method"}
		return a
	}
	if reason := nonConcreteMethodReason(mi); reason != "" {
		a.Reasons = []string{reason}
		return a
	}
	if !strategy.CanApply(mi, mode) {
		a.Reasons = []string{"strategy_declined_method"}
		return a
	}
	a.Applicable = true
	a.Score = float64(strategy.GetPriority())
	// Whole-body strategies must not silently cross exception/coroutine/switch
	// boundaries, even when an older strategy does not expose metadata yet.
	// This keeps legacy third-party strategies behind the same safety floor.
	if hasUnsafeControlFlow(&MethodInfo{RawBody: mi.RawBody, FullSignature: mi.FullSignature}) {
		if d, ok := strategy.(StrategyDescriber); !ok || !d.Metadata().PreservesControlFlow {
			a.Applicable = false
			a.Reasons = append(a.Reasons, "unsafe_control_flow_for_whole_body_strategy")
			return a
		}
	}

	if d, ok := strategy.(StrategyDescriber); ok {
		meta := d.Metadata()
		returnType := mi.ReturnType
		if returnType == "" && mi.ReturnsBoolean {
			returnType = "Z"
		}
		if len(meta.SupportedReturns) > 0 && !containsString(meta.SupportedReturns, returnType) {
			a.Applicable = false
			a.Reasons = append(a.Reasons, "return_type_not_supported")
			return a
		}
		if len(meta.SupportedRoles) > 0 {
			role := inferMethodRole(mi)
			if !containsRole(meta.SupportedRoles, role) {
				a.Applicable = false
				a.Reasons = append(a.Reasons, "method_role_not_supported")
				return a
			}
		}
		if meta.HighRisk {
			a.Warnings = append(a.Warnings, "high_risk_strategy_requires_review")
			a.Score -= 10
		}
		if !meta.PreservesControlFlow && hasUnsafeControlFlow(&MethodInfo{RawBody: mi.RawBody, FullSignature: mi.FullSignature}) {
			a.Applicable = false
			a.Reasons = append(a.Reasons, "unsafe_control_flow_for_whole_body_strategy")
		}
	}
	return a
}

func inferMethodRole(mi *shared.MethodInfo) MethodRole {
	if mi == nil {
		return MethodRoleUnknown
	}
	if mi.IsConstructor {
		return MethodRoleInitializer
	}
	if mi.IsCallback {
		return MethodRoleCallback
	}
	if mi.ReturnsBoolean || mi.ReturnType == "Z" {
		return MethodRoleBooleanGate
	}
	if mi.ReturnsVoid || mi.ReturnType == "V" {
		return MethodRoleWrapper
	}
	return MethodRoleValueProvider
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func containsRole(values []MethodRole, wanted MethodRole) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func strategyAssessmentReason(a StrategyAssessment) string {
	if len(a.Reasons) == 0 {
		return ""
	}
	return fmt.Sprintf("%s", strings.Join(a.Reasons, ","))
}
