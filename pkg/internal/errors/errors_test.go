package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	err := New("something went wrong")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "something went wrong" {
		t.Fatalf("got %q, want %q", err.Error(), "something went wrong")
	}
}

func TestNew_EmptyMessage(t *testing.T) {
	err := New("")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "" {
		t.Fatalf("got %q, want empty string", err.Error())
	}
}

func TestNewf(t *testing.T) {
	err := Newf("file %s not found at line %d", "test.go", 42)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	want := "file test.go not found at line 42"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
}

func TestNewf_NoArgs(t *testing.T) {
	err := Newf("plain message")
	if err.Error() != "plain message" {
		t.Fatalf("got %q", err.Error())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HintError tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestHintError_Error(t *testing.T) {
	he := &HintError{
		err:   fmt.Errorf("base error"),
		hints: []string{"try this"},
	}
	if he.Error() != "base error" {
		t.Fatalf("got %q", he.Error())
	}
}

func TestHintError_Error_NilErr(t *testing.T) {
	he := &HintError{err: nil, hints: []string{"hint"}}
	if he.Error() != "" {
		t.Fatalf("expected empty string for nil err, got %q", he.Error())
	}
}

func TestHintError_Unwrap(t *testing.T) {
	base := fmt.Errorf("base")
	he := &HintError{err: base, hints: []string{"h"}}
	if he.Unwrap() != base {
		t.Fatal("Unwrap should return the base error")
	}
}

func TestHintError_Hints(t *testing.T) {
	hints := []string{"hint1", "hint2", "hint3"}
	he := &HintError{err: fmt.Errorf("x"), hints: hints}
	got := he.Hints()
	if len(got) != 3 {
		t.Fatalf("expected 3 hints, got %d", len(got))
	}
	for i, h := range hints {
		if got[i] != h {
			t.Fatalf("hint[%d] = %q, want %q", i, got[i], h)
		}
	}
}

func TestHintError_String_NilErr(t *testing.T) {
	he := &HintError{err: nil}
	if he.String() != "" {
		t.Fatalf("expected empty string, got %q", he.String())
	}
}

func TestHintError_String_NoHints(t *testing.T) {
	he := &HintError{err: fmt.Errorf("oops"), hints: nil}
	if he.String() != "oops" {
		t.Fatalf("got %q", he.String())
	}
}

func TestHintError_String_WithHints(t *testing.T) {
	he := &HintError{
		err:   fmt.Errorf("file not found"),
		hints: []string{"check path", "use absolute path"},
	}
	s := he.String()
	if !strings.Contains(s, "file not found") {
		t.Fatal("should contain error message")
	}
	if !strings.Contains(s, "Hint: check path") {
		t.Fatal("should contain first hint")
	}
	if !strings.Contains(s, "Hint: use absolute path") {
		t.Fatal("should contain second hint")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// WithHint / WithHints tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestWithHint_NilError(t *testing.T) {
	result := WithHint(nil, "some hint")
	if result != nil {
		t.Fatal("WithHint(nil, ...) should return nil")
	}
}

func TestWithHint_ValidError(t *testing.T) {
	base := fmt.Errorf("something failed")
	result := WithHint(base, "try again")
	if result == nil {
		t.Fatal("expected non-nil")
	}
	he, ok := result.(*HintError)
	if !ok {
		t.Fatal("expected *HintError")
	}
	if he.Error() != "something failed" {
		t.Fatalf("got %q", he.Error())
	}
	if len(he.Hints()) != 1 || he.Hints()[0] != "try again" {
		t.Fatalf("hints = %v", he.Hints())
	}
}

func TestWithHints_NilError(t *testing.T) {
	result := WithHints(nil, "a", "b")
	if result != nil {
		t.Fatal("WithHints(nil, ...) should return nil")
	}
}

func TestWithHints_MultipleHints(t *testing.T) {
	base := fmt.Errorf("err")
	result := WithHints(base, "hint1", "hint2", "hint3")
	he, ok := result.(*HintError)
	if !ok {
		t.Fatal("expected *HintError")
	}
	if len(he.Hints()) != 3 {
		t.Fatalf("expected 3 hints, got %d", len(he.Hints()))
	}
}

func TestWithHints_NoHints(t *testing.T) {
	base := fmt.Errorf("err")
	result := WithHints(base)
	he, ok := result.(*HintError)
	if !ok {
		t.Fatal("expected *HintError")
	}
	if len(he.Hints()) != 0 {
		t.Fatalf("expected 0 hints, got %d", len(he.Hints()))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// WrapWithHint tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestWrapWithHint_NilError(t *testing.T) {
	result := WrapWithHint(nil, "context")
	if result != nil {
		t.Fatal("WrapWithHint(nil, ...) should return nil")
	}
}

func TestWrapWithHint_FileNotFound(t *testing.T) {
	err := fmt.Errorf("file not found: /tmp/x")
	result := WrapWithHint(err, "loading config")
	he, ok := result.(*HintError)
	if !ok {
		t.Fatal("expected *HintError")
	}
	if !strings.Contains(he.Error(), "loading config") {
		t.Fatalf("should contain context, got %q", he.Error())
	}
	found := false
	for _, h := range he.Hints() {
		if h == HintCheckFile {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintCheckFile in hints: %v", he.Hints())
	}
}

func TestWrapWithHint_PermissionDenied(t *testing.T) {
	err := fmt.Errorf("permission denied")
	result := WrapWithHint(err, "opening file")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintCheckPermissions {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintCheckPermissions, got %v", he.Hints())
	}
}

func TestWrapWithHint_APKError(t *testing.T) {
	err := fmt.Errorf("invalid apk format")
	result := WrapWithHint(err, "parsing")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintCheckAPK {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintCheckAPK, got %v", he.Hints())
	}
}

func TestWrapWithHint_DirectoryError(t *testing.T) {
	err := fmt.Errorf("directory not accessible")
	result := WrapWithHint(err, "scanning")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintCheckDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintCheckDir, got %v", he.Hints())
	}
}

func TestWrapWithHint_TimeoutError(t *testing.T) {
	err := fmt.Errorf("operation timed out")
	result := WrapWithHint(err, "analysis")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintTryProfile {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintTryProfile, got %v", he.Hints())
	}
}

func TestWrapWithHint_MemoryError(t *testing.T) {
	err := fmt.Errorf("out of memory")
	result := WrapWithHint(err, "processing")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintIncreaseMemory {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintIncreaseMemory, got %v", he.Hints())
	}
}

func TestWrapWithHint_NetworkError(t *testing.T) {
	err := fmt.Errorf("network connection refused")
	result := WrapWithHint(err, "fetching")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintCheckNetwork {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintCheckNetwork, got %v", he.Hints())
	}
}

func TestWrapWithHint_ConfigError(t *testing.T) {
	err := fmt.Errorf("invalid configuration")
	result := WrapWithHint(err, "loading")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintCheckConfig {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintCheckConfig, got %v", he.Hints())
	}
}

func TestWrapWithHint_AlwaysAddsDebugHint(t *testing.T) {
	err := fmt.Errorf("unknown error xyz")
	result := WrapWithHint(err, "doing stuff")
	he := result.(*HintError)
	found := false
	for _, h := range he.Hints() {
		if h == HintDebug {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HintDebug always present, got %v", he.Hints())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wrap tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestWrap_NilError(t *testing.T) {
	result := Wrap(nil, "context", "hint")
	if result != nil {
		t.Fatal("Wrap(nil, ...) should return nil")
	}
}

func TestWrap_PlainError(t *testing.T) {
	base := fmt.Errorf("base error")
	result := Wrap(base, "context", "hint1", "hint2")
	he, ok := result.(*HintError)
	if !ok {
		t.Fatal("expected *HintError")
	}
	if !strings.Contains(he.Error(), "context") {
		t.Fatalf("should contain context: %q", he.Error())
	}
	if !strings.Contains(he.Error(), "base error") {
		t.Fatalf("should contain base error: %q", he.Error())
	}
	if len(he.Hints()) != 2 {
		t.Fatalf("expected 2 hints, got %d", len(he.Hints()))
	}
}

func TestWrap_ExistingHintError(t *testing.T) {
	base := &HintError{
		err:   fmt.Errorf("original"),
		hints: []string{"existing hint"},
	}
	result := Wrap(base, "new context", "new hint")
	he, ok := result.(*HintError)
	if !ok {
		t.Fatal("expected *HintError")
	}
	// Should prefix original error with context
	if he.Error() != "new context: original" {
		t.Fatalf("got %q, want %q", he.Error(), "new context: original")
	}
	// Should combine hints: [new hints..., existing hints...]
	if len(he.Hints()) != 2 {
		t.Fatalf("expected 2 hints (new + existing), got %d: %v", len(he.Hints()), he.Hints())
	}
	if he.Hints()[0] != "new hint" {
		t.Fatalf("first hint should be 'new hint', got %q", he.Hints()[0])
	}
}

func TestWrap_Unwrappable(t *testing.T) {
	base := fmt.Errorf("base")
	result := Wrap(base, "ctx")
	he := result.(*HintError)
	// The wrapped error should be unwrappable to find the base
	if !errors.Is(he.Unwrap(), base) {
		t.Fatal("should be able to unwrap to base error")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PrintHintError tests (just ensure no panics)
// ═══════════════════════════════════════════════════════════════════════════════

func TestPrintHintError_Nil(t *testing.T) {
	// Should not panic
	PrintHintError(nil)
}

func TestPrintHintError_HintError(t *testing.T) {
	he := &HintError{
		err:   fmt.Errorf("test error"),
		hints: []string{"hint1", "hint2"},
	}
	// Should not panic
	PrintHintError(he)
}

func TestPrintHintError_RegularError(t *testing.T) {
	err := fmt.Errorf("regular error")
	// Should not panic
	PrintHintError(err)
}

func TestPrintHintError_HintErrorNoHints(t *testing.T) {
	he := &HintError{err: fmt.Errorf("no hints")}
	PrintHintError(he)
}
