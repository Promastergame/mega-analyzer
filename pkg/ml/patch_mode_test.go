package ml

import (
	"testing"
)

func TestPatchMode_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		mode     PatchMode
		expected bool
	}{
		{
			name:     "defensive mode is valid",
			mode:     PatchModeDefensive,
			expected: true,
		},
		{
			name:     "research mode is valid",
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name:     "empty mode is invalid",
			mode:     PatchMode(""),
			expected: false,
		},
		{
			name:     "unknown mode is invalid",
			mode:     PatchMode("unknown"),
			expected: false,
		},
		{
			name:     "invalid mode string is invalid",
			mode:     PatchMode("attack"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPatchMode_String(t *testing.T) {
	tests := []struct {
		name     string
		mode     PatchMode
		expected string
	}{
		{
			name:     "defensive mode string",
			mode:     PatchModeDefensive,
			expected: "defensive",
		},
		{
			name:     "research mode string",
			mode:     PatchModeResearch,
			expected: "research",
		},
		{
			name:     "empty mode string",
			mode:     PatchMode(""),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidatePatchMode(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedMode PatchMode
		expectedOk   bool
	}{
		{
			name:         "defensive mode is not accepted from user input",
			input:        "defensive",
			expectedMode: "",
			expectedOk:   false,
		},
		{
			name:         "valid research mode",
			input:        "research",
			expectedMode: PatchModeResearch,
			expectedOk:   true,
		},
		{
			name:         "invalid empty string",
			input:        "",
			expectedMode: "",
			expectedOk:   false,
		},
		{
			name:         "invalid unknown mode",
			input:        "unknown",
			expectedMode: "",
			expectedOk:   false,
		},
		{
			name:         "defensive mode with wrong case is not accepted",
			input:        "Defensive",
			expectedMode: "",
			expectedOk:   false,
		},
		{
			name:         "defensive mode with spaces is not accepted",
			input:        "defensive ",
			expectedMode: "",
			expectedOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, ok := ValidatePatchMode(tt.input)
			if ok != tt.expectedOk {
				t.Errorf("ValidatePatchMode() ok = %v, want %v", ok, tt.expectedOk)
			}
			if mode != tt.expectedMode {
				t.Errorf("ValidatePatchMode() mode = %v, want %v", mode, tt.expectedMode)
			}
		})
	}
}

func TestPatchMode_GetModeIcon(t *testing.T) {
	tests := []struct {
		name     string
		mode     PatchMode
		expected string
	}{
		{
			name:     "defensive mode icon",
			mode:     PatchModeDefensive,
			expected: "🛡️",
		},
		{
			name:     "research mode icon",
			mode:     PatchModeResearch,
			expected: "⚔️",
		},
		{
			name:     "invalid mode returns empty icon",
			mode:     PatchMode("invalid"),
			expected: "❓",
		},
		{
			name:     "empty mode returns empty icon",
			mode:     PatchMode(""),
			expected: "❓",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.GetModeIcon()
			if result != tt.expected {
				t.Errorf("GetModeIcon() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPatchMode_GetModeDescription(t *testing.T) {
	tests := []struct {
		name     string
		mode     PatchMode
		expected string
	}{
		{
			name:     "defensive mode description",
			mode:     PatchModeDefensive,
			expected: "Security hardening mode — generates fixes to strengthen security checks",
		},
		{
			name:     "research mode description",
			mode:     PatchModeResearch,
			expected: "Security research mode — generates bypasses for penetration testing",
		},
		{
			name:     "invalid mode returns unknown description",
			mode:     PatchMode("invalid"),
			expected: "Unknown mode",
		},
		{
			name:     "empty mode returns unknown description",
			mode:     PatchMode(""),
			expected: "Unknown mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.GetModeDescription()
			if result != tt.expected {
				t.Errorf("GetModeDescription() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestPatchMode_Constants verifies the constant values
func TestPatchMode_Constants(t *testing.T) {
	if PatchModeDefensive != "defensive" {
		t.Errorf("PatchModeDefensive = %v, want 'defensive'", PatchModeDefensive)
	}
	if PatchModeResearch != "research" {
		t.Errorf("PatchModeResearch = %v, want 'research'", PatchModeResearch)
	}
}

// TestPatchMode_AllModesAreValid ensures all defined constants are valid
func TestPatchMode_AllModesAreValid(t *testing.T) {
	modes := []PatchMode{
		PatchModeDefensive,
		PatchModeResearch,
	}

	for _, mode := range modes {
		if !mode.IsValid() {
			t.Errorf("Constant mode %v should be valid but IsValid() returned false", mode)
		}
	}
}
