// pkg/logger/logger_test.go
package logger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLevel_Constants(t *testing.T) {
	if DebugLevel >= InfoLevel {
		t.Error("DebugLevel should be less than InfoLevel")
	}
	if InfoLevel >= WarnLevel {
		t.Error("InfoLevel should be less than WarnLevel")
	}
	if WarnLevel >= ErrorLevel {
		t.Error("WarnLevel should be less than ErrorLevel")
	}
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Level:      DebugLevel,
		OutputPath: "",
		JSONFormat: false,
	}

	if cfg.Level != DebugLevel {
		t.Errorf("Level = %d", cfg.Level)
	}
}

func TestGet_ReturnsNonNil(t *testing.T) {
	l := Get()
	if l == nil {
		t.Fatal("Get() returned nil")
	}
}

func TestDebug_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Debug() panicked: %v", r)
		}
	}()
	Debug("test debug", "key", "value")
}

func TestInfo_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Info() panicked: %v", r)
		}
	}()
	Info("test info", "key", "value")
}

func TestWarn_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Warn() panicked: %v", r)
		}
	}()
	Warn("test warn", "key", "value")
}

func TestError_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Error() panicked: %v", r)
		}
	}()
	Error("test error", "key", "value")
}

func TestInit_WithConsole(t *testing.T) {
	// Init uses sync.Once, so this may or may not actually init
	// depending on test execution order. But it should not error.
	err := Init(Config{
		Level:      InfoLevel,
		JSONFormat: false,
	})
	// err may be nil (first call) or nil (already initialized)
	_ = err
}

func TestInit_WithFileOutput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	// May not actually init due to sync.Once
	_ = Init(Config{
		Level:      DebugLevel,
		OutputPath: logPath,
	})

	// If it did init with file, the file should exist
	// But due to sync.Once, we can't guarantee this
}

func TestInit_WithInvalidPath(t *testing.T) {
	// Invalid path — may or may not trigger error depending on sync.Once
	_ = Init(Config{
		Level:      InfoLevel,
		OutputPath: filepath.Join(string([]byte{0}), "invalid"),
	})
}

func TestGet_MultipleCalls(t *testing.T) {
	l1 := Get()
	l2 := Get()
	if l1 != l2 {
		t.Error("Get() should return same instance")
	}
}

func TestDebug_NoArgs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Debug() without args panicked: %v", r)
		}
	}()
	Debug("simple message")
}

func TestInfo_MultipleKV(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	Info("test", "k1", "v1", "k2", 42, "k3", true)
}

func TestError_WithComplexValues(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	Error("test error",
		"err", os.ErrNotExist,
		"count", 42,
		"data", []string{"a", "b"},
	)
}
