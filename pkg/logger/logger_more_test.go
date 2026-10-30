package logger

import (
	"testing"
)

// ─── SetLevel and GetLevel ─────────────────────────────────────────────────

func TestSetLevel_GetLevel_InfoLevel(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	l.SetLevel(InfoLevel)
	if l.GetLevel() != InfoLevel {
		t.Errorf("expected InfoLevel, got %v", l.GetLevel())
	}
}

func TestSetLevel_GetLevel_ErrorLevel(t *testing.T) {
	l, err := New(Config{Level: DebugLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	l.SetLevel(ErrorLevel)
	if l.GetLevel() != ErrorLevel {
		t.Errorf("expected ErrorLevel, got %v", l.GetLevel())
	}
}

func TestSetLevel_GetLevel_DebugLevel(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	l.SetLevel(DebugLevel)
	if l.GetLevel() != DebugLevel {
		t.Errorf("expected DebugLevel, got %v", l.GetLevel())
	}
}

func TestSetLevel_GetLevel_FatalLevel(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	l.SetLevel(FatalLevel)
	if l.GetLevel() != FatalLevel {
		t.Errorf("expected FatalLevel, got %v", l.GetLevel())
	}
}

// ─── With method (creates child logger) ────────────────────────────────────

func TestWith_CreatesChild(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	child := l.With("key", "value")
	if child == nil {
		t.Fatal("expected non-nil child logger")
	}
	if child == l {
		t.Error("expected different logger instance")
	}
}

func TestWith_PreservesLevel(t *testing.T) {
	l, err := New(Config{Level: DebugLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	l.SetLevel(ErrorLevel)
	child := l.With("key", "value")
	if child.GetLevel() != ErrorLevel {
		t.Errorf("expected child to have same level, got %v", child.GetLevel())
	}
}

func TestWith_MultipleKVs(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	child := l.With("k1", "v1", "k2", "v2", "k3", "v3")
	if child == nil {
		t.Fatal("expected non-nil child")
	}
}

func TestWith_EmptyKVs(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	child := l.With()
	if child == nil {
		t.Fatal("expected non-nil child even with no kvs")
	}
}

// ─── Level.String() and methods ────────────────────────────────────────────

func TestLevel_String_DebugLevel(t *testing.T) {
	s := DebugLevel.String()
	if s == "" {
		t.Error("expected non-empty string for DebugLevel")
	}
}

func TestLevel_String_InfoLevel(t *testing.T) {
	s := InfoLevel.String()
	if s == "" {
		t.Error("expected non-empty string for InfoLevel")
	}
}

func TestLevel_String_ErrorLevel(t *testing.T) {
	s := ErrorLevel.String()
	if s == "" {
		t.Error("expected non-empty string for ErrorLevel")
	}
}

func TestLevel_String_FatalLevel(t *testing.T) {
	s := FatalLevel.String()
	if s == "" {
		t.Error("expected non-empty string for FatalLevel")
	}
}

// ─── Level.Color() ────────────────────────────────────────────────────────

func TestLevel_Color_DebugLevel(t *testing.T) {
	c := DebugLevel.Color()
	if c == "" {
		t.Error("expected non-empty color for DebugLevel")
	}
}

func TestLevel_Color_InfoLevel(t *testing.T) {
	c := InfoLevel.Color()
	if c == "" {
		t.Error("expected non-empty color for InfoLevel")
	}
}

func TestLevel_Color_ErrorLevel(t *testing.T) {
	c := ErrorLevel.Color()
	if c == "" {
		t.Error("expected non-empty color for ErrorLevel")
	}
}

// ─── Enabled method ───────────────────────────────────────────────────────

func TestEnabled_DebugAtDebugLevel(t *testing.T) {
	l, err := New(Config{Level: DebugLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	if !l.Enabled(DebugLevel) {
		t.Error("expected DebugLevel to be enabled at DebugLevel")
	}
}

func TestEnabled_InfoAtErrorLevel(t *testing.T) {
	l, err := New(Config{Level: ErrorLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	if l.Enabled(InfoLevel) {
		t.Error("expected InfoLevel to be disabled at ErrorLevel")
	}
}

func TestEnabled_ErrorAtErrorLevel(t *testing.T) {
	l, err := New(Config{Level: ErrorLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	if !l.Enabled(ErrorLevel) {
		t.Error("expected ErrorLevel to be enabled at ErrorLevel")
	}
}

func TestEnabled_FatalAlwaysEnabled(t *testing.T) {
	l, err := New(Config{Level: InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	if !l.Enabled(FatalLevel) {
		t.Error("expected FatalLevel to always be enabled")
	}
}
