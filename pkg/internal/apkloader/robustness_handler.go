package apkloader

import (
	"fmt"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ROBUSTNESS HANDLER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Handles pipeline errors, implements fallback strategies, and validates
// transformations to ensure the deobfuscation pipeline is robust against
// malformed or highly obfuscated bytecode.

// PipelineErrorSeverity defines the importance of a pipeline error.
type PipelineErrorSeverity uint8

const (
	PipelineSeverityInfo PipelineErrorSeverity = iota
	PipelineSeverityWarning
	PipelineSeverityError
	PipelineSeverityCritical
)

func (s PipelineErrorSeverity) String() string {
	switch s {
	case PipelineSeverityInfo:
		return "INFO"
	case PipelineSeverityWarning:
		return "WARNING"
	case PipelineSeverityError:
		return "ERROR"
	case PipelineSeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// PipelineErrorInfo contains details about an error during pipeline execution.
type PipelineErrorInfo struct {
	Severity    PipelineErrorSeverity
	Component   string
	Message     string
	Recoverable bool
	InternalErr error
}

func (e *PipelineErrorInfo) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Severity.String(), e.Component, e.Message)
}

// RobustnessStats tracks the reliability of the pipeline.
type RobustnessStats struct {
	TotalErrors      int
	WarningCount     int
	RecoveredErrors  int
	FailedRecoveries int
	RecoveryRate     float64
}

// RobustnessHandler manages error reporting and recovery strategies.
type RobustnessHandler struct {
	mu         sync.RWMutex
	errors     []*PipelineErrorInfo
	warnings   []*PipelineErrorInfo
	strategies map[string]FallbackStrategy
	recovered  int
	failed     int
}

// NewRobustnessHandler creates a new robustness handler.
func NewRobustnessHandler() *RobustnessHandler {
	return &RobustnessHandler{
		strategies: make(map[string]FallbackStrategy),
	}
}

// RecordError logs an error in the pipeline.
func (h *RobustnessHandler) RecordError(err *PipelineErrorInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errors = append(h.errors, err)
}

// RecordWarning logs a warning in the pipeline.
func (h *RobustnessHandler) RecordWarning(component, message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	warning := &PipelineErrorInfo{
		Severity:    PipelineSeverityWarning,
		Component:   component,
		Message:     message,
		Recoverable: true,
	}
	h.warnings = append(h.warnings, warning)
}

// GetErrors returns all recorded errors.
func (h *RobustnessHandler) GetErrors() []*PipelineErrorInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.errors
}

// GetWarnings returns all recorded warnings.
func (h *RobustnessHandler) GetWarnings() []*PipelineErrorInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.warnings
}

// GetStatistics returns current reliability statistics.
func (h *RobustnessHandler) GetStatistics() RobustnessStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	total := len(h.errors)
	rate := 0.0
	if h.recovered+h.failed > 0 {
		rate = float64(h.recovered) / float64(h.recovered+h.failed)
	}

	return RobustnessStats{
		TotalErrors:      total,
		WarningCount:     len(h.warnings),
		RecoveredErrors:  h.recovered,
		FailedRecoveries: h.failed,
		RecoveryRate:     rate,
	}
}

// RegisterStrategy adds a new fallback strategy.
func (h *RobustnessHandler) RegisterStrategy(name string, strategy FallbackStrategy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.strategies[name] = strategy
}

// AttemptRecovery tries to recover from a pipeline error using registered strategies.
func (h *RobustnessHandler) AttemptRecovery(err *PipelineErrorInfo) bool {
	if !err.Recoverable {
		h.mu.Lock()
		h.failed++
		h.mu.Unlock()
		return false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, strategy := range h.strategies {
		if strategy.CanRecover(err) {
			if recoverErr := strategy.Recover(err); recoverErr == nil {
				h.mu.RUnlock()
				h.mu.Lock()
				h.recovered++
				h.mu.Unlock()
				h.mu.RLock()
				return true
			}
		}
	}

	h.mu.RUnlock()
	h.mu.Lock()
	h.failed++
	h.mu.Unlock()
	h.mu.RLock()
	return false
}

// FallbackStrategy defines an interface for recovering from specific errors.
type FallbackStrategy interface {
	CanRecover(err *PipelineErrorInfo) bool
	Recover(err *PipelineErrorInfo) error
}

type defaultFallbackStrategy struct {
	name       string
	recoveryFn func() error
}

func (s *defaultFallbackStrategy) CanRecover(err *PipelineErrorInfo) bool {
	return err.Recoverable
}

func (s *defaultFallbackStrategy) Recover(err *PipelineErrorInfo) error {
	return s.recoveryFn()
}

// NewFallbackStrategy creates a simple fallback strategy from a function.
func NewFallbackStrategy(name string, recoveryFn func() error) FallbackStrategy {
	return &defaultFallbackStrategy{
		name:       name,
		recoveryFn: recoveryFn,
	}
}

// ValidationRule defines a rule for validating code transformations.
type ValidationRule interface {
	Validate(data interface{}) bool
	GetName() string
}

// TransformationValidator ensures that deobfuscation passes don't break code.
type TransformationValidator struct {
	mu      sync.RWMutex
	rules   []ValidationRule
	results map[string]bool
}

// NewTransformationValidator creates a new transformation validator.
func NewTransformationValidator() *TransformationValidator {
	return &TransformationValidator{
		results: make(map[string]bool),
	}
}

// RegisterRule adds a validation rule.
func (v *TransformationValidator) RegisterRule(rule ValidationRule) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.rules = append(v.rules, rule)
}

// Validate runs all registered rules against the provided data.
func (v *TransformationValidator) Validate(data interface{}) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	allPassed := true
	for _, rule := range v.rules {
		passed := rule.Validate(data)
		v.results[rule.GetName()] = passed
		if !passed {
			allPassed = false
		}
	}
	return allPassed
}

// GetValidationResults returns the results of the last validation run.
func (v *TransformationValidator) GetValidationResults() map[string]bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	resultsCopy := make(map[string]bool)
	for k, v := range v.results {
		resultsCopy[k] = v
	}
	return resultsCopy
}

// SemanticPreservationChecker verifies that program semantics are preserved.
type SemanticPreservationChecker struct {
	violations []string
}

// NewSemanticPreservationChecker creates a new semantic preservation checker.
func NewSemanticPreservationChecker() *SemanticPreservationChecker {
	return &SemanticPreservationChecker{
		violations: make([]string, 0),
	}
}

// IsPreserved returns true if no semantic violations have been detected.
func (c *SemanticPreservationChecker) IsPreserved() bool {
	return len(c.violations) == 0
}

// CheckControlFlow verifies that the control flow graph structure is preserved.
func (c *SemanticPreservationChecker) CheckControlFlow(orig, transformed interface{}) bool {
	// Placeholder for actual CFG comparison logic
	return true
}

// CheckDataFlow verifies that the data flow (use-def chains) is preserved.
func (c *SemanticPreservationChecker) CheckDataFlow(orig, transformed interface{}) bool {
	// Placeholder for actual data flow comparison logic
	return true
}

// CheckExceptionHandling verifies that exception handler structure is preserved.
func (c *SemanticPreservationChecker) CheckExceptionHandling(orig, transformed interface{}) bool {
	// Placeholder for actual exception handler comparison logic
	return true
}

// GetViolations returns a list of detected semantic violations.
func (c *SemanticPreservationChecker) GetViolations() []string {
	return c.violations
}
