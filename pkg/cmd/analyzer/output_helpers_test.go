package main

import (
	"bytes"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestVisibleLen(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"plain text", "hello", 5},
		{"with ANSI codes", "\x1b[31mred\x1b[0m", 3},
		{"empty string", "", 0},
		{"only ANSI codes", "\x1b[31m\x1b[0m", 0},
		{"multiple ANSI codes", "\x1b[1m\x1b[31mbold red\x1b[0m", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := visibleLen(tt.input)
			if result != tt.expected {
				t.Errorf("visibleLen(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPadRight(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		width  int
		minLen int
	}{
		{"short string", "hi", 10, 10},
		{"exact width", "hello", 5, 5},
		{"longer than width", "hello world", 5, 11},
		{"empty string", "", 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padRight(tt.input, tt.width)
			if len(result) < tt.minLen {
				t.Errorf("padRight(%q, %d) length = %d, want >= %d", tt.input, tt.width, len(result), tt.minLen)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		width    int
		minLines int
	}{
		{"short text", "hello", 10, 1},
		{"long text", "this is a very long text that should be wrapped", 10, 2},
		{"empty text", "", 10, 0},
		{"exact width", "hello", 5, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapText(tt.input, tt.width)
			if len(result) < tt.minLines {
				t.Errorf("wrapText(%q, %d) lines = %d, want >= %d", tt.input, tt.width, len(result), tt.minLines)
			}
		})
	}
}

func TestTimestamp(t *testing.T) {
	ts := timestamp()

	if len(ts) == 0 {
		t.Error("timestamp() should not be empty")
	}

	// Should contain time components
	if !strings.Contains(ts, ":") {
		t.Errorf("timestamp() = %q, should contain ':'", ts)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET PATCH LABEL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetPatchLabel(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		isHighRisk bool
		expected   string
	}{
		{"defensive mode", "defensive", false, "Weakness"},
		{"research mode", "research", false, "Exploit suggestion"},
		{"high risk defensive", "defensive", true, "Impact"},
		{"high risk research", "research", true, "Bypass"},
		{"unknown mode", "unknown", false, "Exploit suggestion"},
		{"empty mode", "", false, "Exploit suggestion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPatchLabel(tt.mode, tt.isHighRisk)
			if result != tt.expected {
				t.Errorf("GetPatchLabel(%s, %v) = %q, want %q", tt.mode, tt.isHighRisk, result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT METHOD TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestOutput_Print(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true) // no color
	output := NewOutputWithWriter(theme, false, &buf)

	output.Print("test message")

	if !strings.Contains(buf.String(), "test message") {
		t.Errorf("output should contain 'test message', got %q", buf.String())
	}
}

func TestOutput_Println(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Println("test", "message")

	result := buf.String()
	if !strings.Contains(result, "test") || !strings.Contains(result, "message") {
		t.Errorf("output should contain 'test' and 'message', got %q", result)
	}
}

func TestOutput_Success(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Success("operation completed")

	if !strings.Contains(buf.String(), "operation completed") {
		t.Errorf("output should contain 'operation completed', got %q", buf.String())
	}
}

func TestOutput_Info(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Info("information message")

	if !strings.Contains(buf.String(), "information message") {
		t.Errorf("output should contain 'information message', got %q", buf.String())
	}
}

func TestOutput_Debug(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Debug("debug message")

	if !strings.Contains(buf.String(), "debug message") {
		t.Errorf("output should contain 'debug message', got %q", buf.String())
	}
}

func TestOutput_Warning(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Warning("warning message")

	if output.WarningCount() != 1 {
		t.Errorf("WarningCount() = %d, want 1", output.WarningCount())
	}

	if !strings.Contains(buf.String(), "warning message") {
		t.Errorf("output should contain 'warning message', got %q", buf.String())
	}
}

func TestOutput_Error(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Error("error message")

	if output.ErrorCount() != 1 {
		t.Errorf("ErrorCount() = %d, want 1", output.ErrorCount())
	}

	if !strings.Contains(buf.String(), "error message") {
		t.Errorf("output should contain 'error message', got %q", buf.String())
	}
}

func TestOutput_Critical(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.Critical("critical message")

	if output.CriticalCount() != 1 {
		t.Errorf("CriticalCount() = %d, want 1", output.CriticalCount())
	}

	if !strings.Contains(buf.String(), "critical message") {
		t.Errorf("output should contain 'critical message', got %q", buf.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COUNTER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestOutput_ErrorCount(t *testing.T) {
	theme := DetectTheme(true)
	output := NewOutput(theme, false)

	if output.ErrorCount() != 0 {
		t.Errorf("initial ErrorCount() = %d, want 0", output.ErrorCount())
	}

	output.Error("error 1")
	output.Error("error 2")

	if output.ErrorCount() != 2 {
		t.Errorf("ErrorCount() = %d, want 2", output.ErrorCount())
	}
}

func TestOutput_WarningCount(t *testing.T) {
	theme := DetectTheme(true)
	output := NewOutput(theme, false)

	if output.WarningCount() != 0 {
		t.Errorf("initial WarningCount() = %d, want 0", output.WarningCount())
	}

	output.Warning("warning 1")
	output.Warning("warning 2")
	output.Warning("warning 3")

	if output.WarningCount() != 3 {
		t.Errorf("WarningCount() = %d, want 3", output.WarningCount())
	}
}

func TestOutput_CriticalCount(t *testing.T) {
	theme := DetectTheme(true)
	output := NewOutput(theme, false)

	if output.CriticalCount() != 0 {
		t.Errorf("initial CriticalCount() = %d, want 0", output.CriticalCount())
	}

	output.Critical("critical 1")

	if output.CriticalCount() != 1 {
		t.Errorf("CriticalCount() = %d, want 1", output.CriticalCount())
	}
}

func TestOutput_HasErrors(t *testing.T) {
	theme := DetectTheme(true)
	output := NewOutput(theme, false)

	if output.HasErrors() {
		t.Error("HasErrors() should be false initially")
	}

	output.Error("test error")

	if !output.HasErrors() {
		t.Error("HasErrors() should be true after error")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIPELINE ERROR/WARNING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestOutput_PipelineError(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.PipelineError("test stage", nil, "detail 1", "detail 2")

	result := buf.String()
	if !strings.Contains(result, "test stage") {
		t.Errorf("output should contain 'test stage', got %q", result)
	}
}

func TestOutput_PipelineWarning(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.PipelineWarning("test stage", "warning message", "detail 1")

	result := buf.String()
	if !strings.Contains(result, "test stage") {
		t.Errorf("output should contain 'test stage', got %q", result)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BOXED OUTPUT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestOutput_BoxedError(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.BoxedError("Error Title", "Error body message")

	result := buf.String()
	if !strings.Contains(result, "Error Title") {
		t.Errorf("output should contain 'Error Title', got %q", result)
	}
}

func TestOutput_BoxedWarning(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	output.BoxedWarning("Warning Title", "Warning body message")

	result := buf.String()
	if !strings.Contains(result, "Warning Title") {
		t.Errorf("output should contain 'Warning Title', got %q", result)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUIET MODE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestOutput_QuietMode(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, true, &buf)

	output.Print("test message")
	output.Info("info message")
	output.Debug("debug message")

	// In quiet mode, these should not produce output
	result := buf.String()
	if len(result) > 0 {
		t.Errorf("quiet mode should suppress output, got %q", result)
	}
}

func TestOutput_QuietMode_ErrorsStillShow(t *testing.T) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, true, &buf)

	output.Error("error message")

	// Errors should still show in quiet mode
	result := buf.String()
	if !strings.Contains(result, "error message") {
		t.Errorf("errors should show in quiet mode, got %q", result)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkVisibleLen(b *testing.B) {
	text := "\x1b[31mcolored text\x1b[0m with normal text"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = visibleLen(text)
	}
}

func BenchmarkWrapText(b *testing.B) {
	text := "This is a long text that needs to be wrapped into multiple lines for display purposes"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wrapText(text, 40)
	}
}

func BenchmarkOutput_Print(b *testing.B) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		output.Print("test message")
	}
}

func BenchmarkOutput_Error(b *testing.B) {
	var buf bytes.Buffer
	theme := DetectTheme(true)
	output := NewOutputWithWriter(theme, false, &buf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		output.Error("error message")
	}
}
