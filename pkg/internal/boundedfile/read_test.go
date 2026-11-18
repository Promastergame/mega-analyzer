package boundedfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(path, 5); err != nil || string(data) != "12345" {
		t.Fatalf("boundary rejected: %q %v", data, err)
	}
	if data, err := ReadFile(path, 4); !errors.Is(err, ErrLimit) || data != nil {
		t.Fatalf("over-limit read accepted: %q %v", data, err)
	}
}
