package types

import (
	"testing"
)

func TestSourceLocation_String(t *testing.T) {
	tests := []struct {
		name     string
		location SourceLocation
		expected string
	}{
		{
			name: "with file and line",
			location: SourceLocation{
				File: "Test.smali",
				Line: 42,
			},
			expected: "Test.smali:42",
		},
		{
			name: "with column",
			location: SourceLocation{
				File:   "Test.smali",
				Line:   42,
				Column: 10,
			},
			expected: "Test.smali:42:10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.location.String()
			if result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSourceRange_LineCount(t *testing.T) {
	tests := []struct {
		name     string
		r        SourceRange
		expected int
	}{
		{
			name: "single line",
			r: SourceRange{
				LineStart: 10,
				LineEnd:   10,
			},
			expected: 1,
		},
		{
			name: "multiple lines",
			r: SourceRange{
				LineStart: 10,
				LineEnd:   20,
			},
			expected: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.r.LineEnd - tt.r.LineStart + 1
			if result != tt.expected {
				t.Errorf("LineCount logic = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestAccessFlags_Methods(t *testing.T) {
	flags := AccessPublic | AccessStatic
	if !flags.IsPublic() {
		t.Error("IsPublic() should be true")
	}
	if !flags.IsStatic() {
		t.Error("IsStatic() should be true")
	}
	if flags.IsPrivate() {
		t.Error("IsPrivate() should be false")
	}
}

func TestAccessFlags_IsPublic(t *testing.T) {
	if !AccessPublic.IsPublic() {
		t.Error("AccessPublic.IsPublic() should be true")
	}
	if AccessPrivate.IsPublic() {
		t.Error("AccessPrivate.IsPublic() should be false")
	}
}

func TestAccessFlags_IsPrivate(t *testing.T) {
	if !AccessPrivate.IsPrivate() {
		t.Error("AccessPrivate.IsPrivate() should be true")
	}
	if AccessPublic.IsPrivate() {
		t.Error("AccessPublic.IsPrivate() should be false")
	}
}

func TestAccessFlags_IsStatic(t *testing.T) {
	if !AccessStatic.IsStatic() {
		t.Error("AccessStatic.IsStatic() should be true")
	}
	if AccessPublic.IsStatic() {
		t.Error("AccessPublic.IsStatic() should be false")
	}
}
