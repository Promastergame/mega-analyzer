package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Evidence is a machine-readable explanation for a patch candidate. Value is
// intentionally kept short because it is emitted in JSON and reports.
type Evidence struct {
	Kind   string  `json:"kind"`
	Value  string  `json:"value"`
	Weight float64 `json:"weight,omitempty"`
	Source string  `json:"source,omitempty"`
}

type CandidateStatus string

const (
	CandidateReady    CandidateStatus = "ready"
	CandidateReview   CandidateStatus = "review"
	CandidateBlocked  CandidateStatus = "blocked"
	CandidateNoTarget CandidateStatus = "no_target"
)

// PatchCandidate is the review boundary between scoring and patch applying.
// It does not apply a patch and is safe to serialize or send to an API.
type PatchCandidate struct {
	ID              string                    `json:"id"`
	Target          string                    `json:"target"`
	FilePath        string                    `json:"file_path"`
	Method          string                    `json:"method"`
	PatchType       PatchType                 `json:"patch_type"`
	Score           float64                   `json:"score"`
	Confidence      float64                   `json:"confidence"`
	Risk            RiskClass                 `json:"risk"`
	Status          CandidateStatus           `json:"status"`
	RequiresReview  bool                      `json:"requires_review"`
	Reasons         []string                  `json:"reasons,omitempty"`
	Warnings        []string                  `json:"warnings,omitempty"`
	Evidence        []Evidence                `json:"evidence,omitempty"`
	SafetyReason    string                    `json:"safety_reason,omitempty"`
	SourceHash      string                    `json:"source_hash,omitempty"`
	Policy          ReviewPolicy              `json:"policy"`
	Dependency      ServerDependency          `json:"dependency"`
	Recommendations []DefensiveRecommendation `json:"recommendations,omitempty"`
}

// BuildPatchCandidate converts an existing score into an explainable review
// object. Existing scoring and patch generation APIs remain unchanged.
func BuildPatchCandidate(sm *ScoredMethod) *PatchCandidate {
	if sm == nil {
		return nil
	}
	m := &sm.Method
	s := &sm.Score
	c := &PatchCandidate{
		ID:              patchCandidateID(m),
		Target:          string(s.PatchCategory),
		FilePath:        m.FilePath,
		Method:          m.FullSignature,
		PatchType:       s.SuggestedPatch,
		Score:           s.FinalScore,
		Confidence:      clamp01(s.Confidence),
		Risk:            s.RiskLevel,
		Status:          CandidateReview,
		RequiresReview:  true,
		Reasons:         append([]string(nil), s.Reasons...),
		Warnings:        append([]string(nil), s.Warnings...),
		SourceHash:      methodSourceHash(m),
		Policy:          DefaultReviewPolicy(ScopeAudit),
		Dependency:      ClassifyServerDependency(m),
		Recommendations: BuildDefensiveRecommendations(m),
	}
	for _, signal := range s.MatchedSignals {
		c.Evidence = append(c.Evidence, Evidence{Kind: string(signal.Type), Value: signal.Value, Weight: signal.Weight, Source: "scorer"})
	}
	for _, part := range s.MatchedParts {
		c.Evidence = append(c.Evidence, Evidence{Kind: "match", Value: part, Source: "pattern"})
	}
	if s.SuggestedPatch == "" {
		c.Status = CandidateNoTarget
		c.SafetyReason = "no_patch_strategy"
		return c
	}
	if allowed, reason := safeRecommendationDecision(sm); !allowed {
		c.Status = CandidateBlocked
		c.SafetyReason = reason
		return c
	}
	if c.Confidence >= 0.8 && c.Risk == RiskClassLow {
		c.Status = CandidateReady
		c.RequiresReview = false
	}
	return c
}

// PreflightPatchCandidate validates only recommendation safety. It deliberately
// does not claim that a generated Smali body will build; SmaliValidator must be
// run after generation as the second preflight stage.
func PreflightPatchCandidate(sm *ScoredMethod) (CandidateStatus, string) {
	c := BuildPatchCandidate(sm)
	if c == nil {
		return CandidateBlocked, "missing_method"
	}
	if c.Status == CandidateBlocked || c.Status == CandidateNoTarget {
		return c.Status, c.SafetyReason
	}
	if reason := incompatiblePatchType(sm.Method.ReturnType, c.PatchType); reason != "" {
		return CandidateBlocked, reason
	}
	return c.Status, ""
}

func incompatiblePatchType(returnType string, patch PatchType) string {
	returnType = strings.TrimSpace(returnType)
	switch patch {
	case PatchReturnTrue, PatchReturnFalse:
		if returnType != "Z" {
			return "boolean_patch_on_non_boolean_return"
		}
	case PatchReturnVoid:
		if returnType != "V" {
			return "void_patch_on_non_void_return"
		}
	case PatchReturnMaxInt, PatchReturnZero:
		if returnType != "I" && returnType != "B" && returnType != "S" && returnType != "C" {
			return "integer_patch_on_non_integer_return"
		}
	case PatchNop, PatchRemoveCheck, PatchConstReplace:
		// These strategies require generated-body validation and are not rejected
		// solely from the method return type.
	default:
		return "unknown_patch_strategy"
	}
	return ""
}

func patchCandidateID(mi *MethodInfo) string {
	h := sha256.Sum256([]byte(mi.FilePath + "\x00" + mi.FullSignature + "\x00" + mi.Name))
	return "candidate_" + hex.EncodeToString(h[:8])
}

func methodSourceHash(mi *MethodInfo) string {
	if mi == nil {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(mi.RawBody, "\n")))
	return hex.EncodeToString(h[:])
}

func (c PatchCandidate) String() string {
	return fmt.Sprintf("%s %s %s (%s)", c.ID, c.Method, c.PatchType, c.Status)
}
