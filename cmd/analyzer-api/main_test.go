package main

import (
	"testing"
)

func TestRun(t *testing.T) {
	code := run([]string{"-test-run-only", "-port", "5000"})
	if code != 0 {
		t.Errorf("expected 0, got %d", code)
	}

	code = run([]string{"-invalidflag"})
	if code != 1 {
		t.Errorf("expected 1, got %d", code)
	}
}
