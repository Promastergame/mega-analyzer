package apkloader

import (
	"errors"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ROBUSTNESS HANDLER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewRobustnessHandler(t *testing.T) {
	handler := NewRobustnessHandler()

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}

	stats := handler.GetStatistics()
	if stats.TotalErrors != 0 {
		t.Fatal("Expected zero initial errors")
	}
}

func TestRecordError(t *testing.T) {
	handler := NewRobustnessHandler()

	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "TestComponent",
		Message:     "Test error",
		Recoverable: true,
	}

	handler.RecordError(err)

	errors := handler.GetErrors()
	if len(errors) != 1 {
		t.Fatal("Expected one error")
	}

	if errors[0].Message != "Test error" {
		t.Fatalf("Expected message 'Test error', got %s", errors[0].Message)
	}
}

func TestRecordWarning(t *testing.T) {
	handler := NewRobustnessHandler()

	handler.RecordWarning("TestComponent", "Test warning")

	warnings := handler.GetWarnings()
	if len(warnings) != 1 {
		t.Fatal("Expected one warning")
	}

	if warnings[0].Message != "Test warning" {
		t.Fatalf("Expected message 'Test warning', got %s", warnings[0].Message)
	}
}

func TestErrorSeverityString(t *testing.T) {
	tests := []struct {
		severity PipelineErrorSeverity
		expected string
	}{
		{PipelineSeverityInfo, "INFO"},
		{PipelineSeverityWarning, "WARNING"},
		{PipelineSeverityError, "ERROR"},
		{PipelineSeverityCritical, "CRITICAL"},
	}

	for _, test := range tests {
		if test.severity.String() != test.expected {
			t.Fatalf("Expected %s, got %s", test.expected, test.severity.String())
		}
	}
}

func TestPipelineErrorInfoError(t *testing.T) {
	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "TestComponent",
		Message:     "Test error",
		Recoverable: true,
	}

	errStr := err.Error()
	if errStr == "" {
		t.Fatal("Expected non-empty error string")
	}

	if !testContains(errStr, "TestComponent") {
		t.Fatalf("Expected component name in error string: %s", errStr)
	}

	if !testContains(errStr, "Test error") {
		t.Fatalf("Expected message in error string: %s", errStr)
	}
}

func TestRegisterStrategy(t *testing.T) {
	handler := NewRobustnessHandler()

	strategy := NewFallbackStrategy("TestStrategy", func() error {
		return nil
	})

	handler.RegisterStrategy("TestStrategy", strategy)

	// Verify strategy is registered by attempting recovery
	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "TestComponent",
		Message:     "Test error",
		Recoverable: true,
	}

	recovered := handler.AttemptRecovery(err)
	if !recovered {
		t.Fatal("Expected recovery to succeed")
	}
}

func TestAttemptRecoveryNonRecoverable(t *testing.T) {
	handler := NewRobustnessHandler()

	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityCritical,
		Component:   "TestComponent",
		Message:     "Critical error",
		Recoverable: false,
	}

	recovered := handler.AttemptRecovery(err)
	if recovered {
		t.Fatal("Expected recovery to fail for non-recoverable error")
	}

	stats := handler.GetStatistics()
	if stats.FailedRecoveries != 1 {
		t.Fatal("Expected failed recovery count to be 1")
	}
}

func TestRobustnessGetStatistics(t *testing.T) {
	handler := NewRobustnessHandler()

	// Record some errors
	for i := 0; i < 3; i++ {
		err := &PipelineErrorInfo{
			Severity:    PipelineSeverityError,
			Component:   "TestComponent",
			Message:     "Test error",
			Recoverable: true,
		}
		handler.RecordError(err)
	}

	stats := handler.GetStatistics()

	if stats.TotalErrors != 3 {
		t.Fatalf("Expected 3 errors, got %d", stats.TotalErrors)
	}

	if stats.WarningCount != 0 {
		t.Fatalf("Expected 0 warnings, got %d", stats.WarningCount)
	}
}

func TestRecoveryRate(t *testing.T) {
	handler := NewRobustnessHandler()

	// Register a recovery strategy
	strategy := NewFallbackStrategy("TestStrategy", func() error {
		return nil
	})
	handler.RegisterStrategy("TestStrategy", strategy)

	// Record and recover from errors
	for i := 0; i < 2; i++ {
		err := &PipelineErrorInfo{
			Severity:    PipelineSeverityError,
			Component:   "TestComponent",
			Message:     "Test error",
			Recoverable: true,
		}
		handler.RecordError(err)
		handler.AttemptRecovery(err)
	}

	stats := handler.GetStatistics()

	if stats.RecoveryRate != 1.0 {
		t.Fatalf("Expected recovery rate 1.0, got %f", stats.RecoveryRate)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FALLBACK STRATEGY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewFallbackStrategy(t *testing.T) {
	strategy := NewFallbackStrategy("TestStrategy", func() error {
		return nil
	})

	if strategy == nil {
		t.Fatal("Expected non-nil strategy")
	}
}

func TestFallbackStrategyCanRecover(t *testing.T) {
	strategy := NewFallbackStrategy("TestStrategy", func() error {
		return nil
	})

	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "TestComponent",
		Message:     "Test error",
		Recoverable: true,
	}

	if !strategy.CanRecover(err) {
		t.Fatal("Expected strategy to be able to recover")
	}
}

func TestFallbackStrategyRecover(t *testing.T) {
	strategy := NewFallbackStrategy("TestStrategy", func() error {
		return nil
	})

	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "TestComponent",
		Message:     "Test error",
		Recoverable: true,
	}

	recoverErr := strategy.Recover(err)
	if recoverErr != nil {
		t.Fatalf("Expected recovery to succeed, got error: %v", recoverErr)
	}
}

func TestFallbackStrategyRecoverWithError(t *testing.T) {
	expectedErr := errors.New("recovery failed")
	strategy := NewFallbackStrategy("TestStrategy", func() error {
		return expectedErr
	})

	err := &PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "TestComponent",
		Message:     "Test error",
		Recoverable: true,
	}

	recoverErr := strategy.Recover(err)
	if recoverErr != expectedErr {
		t.Fatalf("Expected recovery error, got: %v", recoverErr)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSFORMATION VALIDATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewTransformationValidator(t *testing.T) {
	validator := NewTransformationValidator()

	if validator == nil {
		t.Fatal("Expected non-nil validator")
	}
}

func TestRegisterValidationRule(t *testing.T) {
	validator := NewTransformationValidator()

	rule := &TestValidationRule{
		name: "TestRule",
	}

	validator.RegisterRule(rule)

	// Verify rule is registered by validating
	result := validator.Validate(nil)
	if !result {
		t.Fatal("Expected validation to pass")
	}
}

func TestValidationResults(t *testing.T) {
	validator := NewTransformationValidator()

	rule := &TestValidationRule{
		name: "TestRule",
	}

	validator.RegisterRule(rule)
	validator.Validate(nil)

	results := validator.GetValidationResults()
	if len(results) != 1 {
		t.Fatal("Expected one validation result")
	}

	if !results["TestRule"] {
		t.Fatal("Expected TestRule to pass")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEMANTIC PRESERVATION CHECKER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewSemanticPreservationChecker(t *testing.T) {
	checker := NewSemanticPreservationChecker()

	if checker == nil {
		t.Fatal("Expected non-nil checker")
	}

	if !checker.IsPreserved() {
		t.Fatal("Expected no violations initially")
	}
}

func TestCheckControlFlow(t *testing.T) {
	checker := NewSemanticPreservationChecker()

	result := checker.CheckControlFlow(nil, nil)
	if !result {
		t.Fatal("Expected control flow check to pass")
	}

	if !checker.IsPreserved() {
		t.Fatal("Expected semantics to be preserved")
	}
}

func TestCheckDataFlow(t *testing.T) {
	checker := NewSemanticPreservationChecker()

	result := checker.CheckDataFlow(nil, nil)
	if !result {
		t.Fatal("Expected data flow check to pass")
	}

	if !checker.IsPreserved() {
		t.Fatal("Expected semantics to be preserved")
	}
}

func TestCheckExceptionHandling(t *testing.T) {
	checker := NewSemanticPreservationChecker()

	result := checker.CheckExceptionHandling(nil, nil)
	if !result {
		t.Fatal("Expected exception handling check to pass")
	}

	if !checker.IsPreserved() {
		t.Fatal("Expected semantics to be preserved")
	}
}

func TestGetViolations(t *testing.T) {
	checker := NewSemanticPreservationChecker()

	violations := checker.GetViolations()
	if len(violations) != 0 {
		t.Fatal("Expected no violations initially")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONCURRENT ACCESS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestConcurrentErrorRecording(t *testing.T) {
	handler := NewRobustnessHandler()

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			err := &PipelineErrorInfo{
				Severity:    PipelineSeverityError,
				Component:   "TestComponent",
				Message:     "Test error",
				Recoverable: true,
			}
			handler.RecordError(err)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	stats := handler.GetStatistics()
	if stats.TotalErrors != 10 {
		t.Fatalf("Expected 10 errors, got %d", stats.TotalErrors)
	}
}

func TestConcurrentValidation(t *testing.T) {
	validator := NewTransformationValidator()

	rule := &TestValidationRule{
		name: "TestRule",
	}

	validator.RegisterRule(rule)

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			_ = validator.Validate(nil)
			_ = validator.GetValidationResults()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

type TestValidationRule struct {
	name string
}

func (tvr *TestValidationRule) Validate(data interface{}) bool {
	return true
}

func (tvr *TestValidationRule) GetName() string {
	return tvr.name
}

func testContains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
