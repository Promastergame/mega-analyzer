package stringutils

import (
	"testing"
)

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		keywords []string
		want     bool
	}{
		{
			name:     "no match",
			target:   "hello world",
			keywords: []string{"foo", "bar"},
			want:     false,
		},
		{
			name:     "single match",
			target:   "hello world",
			keywords: []string{"foo", "world"},
			want:     true,
		},
		{
			name:     "multiple matches",
			target:   "hello world",
			keywords: []string{"hello", "world"},
			want:     true,
		},
		{
			name:     "empty keywords",
			target:   "hello world",
			keywords: []string{},
			want:     false,
		},
		{
			name:     "case sensitive",
			target:   "Hello World",
			keywords: []string{"hello"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsAny(tt.target, tt.keywords); got != tt.want {
				t.Errorf("ContainsAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainsAnyFold(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		keywords []string
		want     bool
	}{
		{
			name:     "no match",
			target:   "hello world",
			keywords: []string{"foo", "bar"},
			want:     false,
		},
		{
			name:     "case insensitive match",
			target:   "Hello World",
			keywords: []string{"hello"},
			want:     true,
		},
		{
			name:     "mixed case keywords",
			target:   "Hello World",
			keywords: []string{"HELLO", "WORLD"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsAnyFold(tt.target, tt.keywords); got != tt.want {
				t.Errorf("ContainsAnyFold() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainsAll(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		keywords []string
		want     bool
	}{
		{
			name:     "all present",
			target:   "hello world",
			keywords: []string{"hello", "world"},
			want:     true,
		},
		{
			name:     "partial match",
			target:   "hello world",
			keywords: []string{"hello", "foo"},
			want:     false,
		},
		{
			name:     "empty keywords",
			target:   "hello world",
			keywords: []string{},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsAll(tt.target, tt.keywords); got != tt.want {
				t.Errorf("ContainsAll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSliceContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		keywords []string
		want     bool
	}{
		{
			name:     "match in slice",
			lines:    []string{"hello", "world", "foo"},
			keywords: []string{"world"},
			want:     true,
		},
		{
			name:     "no match in slice",
			lines:    []string{"hello", "world", "foo"},
			keywords: []string{"bar"},
			want:     false,
		},
		{
			name:     "empty slice",
			lines:    []string{},
			keywords: []string{"foo"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SliceContainsAny(tt.lines, tt.keywords); got != tt.want {
				t.Errorf("SliceContainsAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSliceContainsAnyFold(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		keywords []string
		want     bool
	}{
		{
			name:     "case insensitive match",
			lines:    []string{"Hello", "World", "Foo"},
			keywords: []string{"hello"},
			want:     true,
		},
		{
			name:     "no match",
			lines:    []string{"Hello", "World", "Foo"},
			keywords: []string{"bar"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SliceContainsAnyFold(tt.lines, tt.keywords); got != tt.want {
				t.Errorf("SliceContainsAnyFold() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSliceContains(t *testing.T) {
	tests := []struct {
		name   string
		lines  []string
		needle string
		want   bool
	}{
		{
			name:   "needle found",
			lines:  []string{"hello", "world", "foo"},
			needle: "world",
			want:   true,
		},
		{
			name:   "needle not found",
			lines:  []string{"hello", "world", "foo"},
			needle: "bar",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SliceContains(tt.lines, tt.needle); got != tt.want {
				t.Errorf("SliceContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSliceContainsFold(t *testing.T) {
	tests := []struct {
		name   string
		lines  []string
		needle string
		want   bool
	}{
		{
			name:   "case insensitive match",
			lines:  []string{"Hello", "World", "Foo"},
			needle: "hello",
			want:   true,
		},
		{
			name:   "no match",
			lines:  []string{"Hello", "World", "Foo"},
			needle: "bar",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SliceContainsFold(tt.lines, tt.needle); got != tt.want {
				t.Errorf("SliceContainsFold() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToLowerIfEmpty(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		cached string
		want   string
	}{
		{
			name:   "empty cache returns lowercase",
			s:      "Hello",
			cached: "",
			want:   "hello",
		},
		{
			name:   "non-empty cache returns cached",
			s:      "Hello",
			cached: "world",
			want:   "world",
		},
		{
			name:   "empty string",
			s:      "",
			cached: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToLowerIfEmpty(tt.s, tt.cached); got != tt.want {
				t.Errorf("ToLowerIfEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeToLower(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "normal string",
			s:    "Hello",
			want: "hello",
		},
		{
			name: "empty string",
			s:    "",
			want: "",
		},
		{
			name: "already lowercase",
			s:    "hello",
			want: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SafeToLower(tt.s); got != tt.want {
				t.Errorf("SafeToLower() = %v, want %v", got, tt.want)
			}
		})
	}
}
