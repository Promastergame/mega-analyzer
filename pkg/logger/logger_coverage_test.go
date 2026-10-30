package logger

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestLevels(t *testing.T) {
	levels := []Level{DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel}
	for _, l := range levels {
		if l.String() == "" {
			t.Errorf("level %d has no string name", l)
		}
		if l.Color() == "" {
			t.Errorf("level %d has no color", l)
		}
		if l.ColorTag() == "" {
			t.Errorf("level %d has no color tag", l)
		}
	}

	// Test out of bounds
	if Level(-10).idx() != 0 {
		t.Error("Level(-10).idx() should be 0")
	}
	if Level(10).idx() != 5 {
		t.Error("Level(10).idx() should be 5")
	}
}

func TestConfigOutput(t *testing.T) {
	tmpFile := "test_log.log"
	defer os.Remove(tmpFile)

	l, err := New(Config{
		Level:      DebugLevel,
		OutputPath: tmpFile,
		NoColor:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	l.Debug("test debug message", "key", "value")
	l.Info("test info message")

	l.Close() // Ensure any async (though not enabled here) or flush happens or file is closed if we had a closer handle

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "test debug message") {
		t.Error("log file missing debug message")
	}
	if !strings.Contains(content, "key=value") {
		t.Error("log file missing fields")
	}
}

type mockWriter struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}

func TestLoggerVariations(t *testing.T) {
	mw := &mockWriter{}

	t.Run("JSON", func(t *testing.T) {
		l, _ := New(Config{JSONFormat: true})
		l.writers = []io.Writer{mw}
		l.Info("json message", "int", 123, "bool", true, "err", errors.New("boom"))

		content := mw.buf.String()
		if !strings.Contains(content, `"msg":"json message"`) {
			t.Error("Missing message in JSON")
		}
		if !strings.Contains(content, `"int":123`) {
			t.Error("Missing int field")
		}
		if !strings.Contains(content, `"bool":true`) {
			t.Error("Missing bool field")
		}
		if !strings.Contains(content, `"err":"boom"`) {
			t.Error("Missing error field")
		}
		mw.buf.Reset()
	})

	t.Run("ConsoleNoColor", func(t *testing.T) {
		l, _ := New(Config{NoColor: true})
		l.writers = []io.Writer{mw}
		l.Warn("console message", "float", 1.23, "uint", uint64(456))

		content := mw.buf.String()
		if !strings.Contains(content, "[WARN]") {
			t.Error("Missing level tag")
		}
		if !strings.Contains(content, "float=1.23") {
			t.Error("Missing float field")
		}
		mw.buf.Reset()
	})
}

func TestAsyncLogger(t *testing.T) {
	mw := &mockWriter{}
	l, _ := New(Config{
		AsyncWrites: true,
		AsyncBufLen: 10,
	})
	l.writers = []io.Writer{mw}

	l.Info("async message")
	l.Error("crit message")

	l.Close() // Should wait for worker

	content := mw.buf.String()
	if !strings.Contains(content, "async message") {
		t.Error("Missing async message")
	}
	if !strings.Contains(content, "crit message") {
		t.Error("Missing crit message")
	}
}

func TestWith(t *testing.T) {
	mw := &mockWriter{}
	l, _ := New(Config{NoColor: true})
	l.writers = []io.Writer{mw}

	child := l.With("request_id", "abc-123")
	child.Info("child message", "user", "bob")

	content := mw.buf.String()
	if !strings.Contains(content, "request_id=abc-123") {
		t.Error("Missing preset field")
	}
	if !strings.Contains(content, "user=bob") {
		t.Error("Missing local field")
	}
	mw.buf.Reset()
}

func TestGlobal(t *testing.T) {
	mw := &mockWriter{}
	l, _ := New(Config{NoColor: true})
	l.writers = []io.Writer{mw}

	SetGlobal(l)
	Info("global message")

	if !strings.Contains(mw.buf.String(), "global message") {
		t.Error("Global function didn't use our logger")
	}
}

func TestJSONValueTypes(t *testing.T) {
	var buf bytes.Buffer

	values := []any{
		int8(1), int16(2), int32(3), uint(4), uint8(5), uint16(6), uint32(7), float32(8.8),
		nil,
	}

	for _, v := range values {
		buf.Reset()
		appendJSONValue(&buf, v)
		if buf.Len() == 0 {
			t.Errorf("type %T failed to encode", v)
		}
	}
}
