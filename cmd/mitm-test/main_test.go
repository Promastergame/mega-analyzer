package main

import (
	"testing"
)

func TestRun(t *testing.T) {
	code := run([]string{"-test-run-only"})
	if code != 0 {
		t.Errorf("expected 0, got %d", code)
	}
	code = run([]string{})
	if code != 1 {
		t.Errorf("expected 1, got %d", code)
	}
}
