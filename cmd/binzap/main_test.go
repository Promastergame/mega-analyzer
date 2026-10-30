package main

import (
	"testing"
)

func TestRun(t *testing.T) {
	code := run([]string{"-invalidflag"})
	if code != 1 {
		t.Errorf("expected 1, got %d", code)
	}

	code = run([]string{})
	if code != 1 {
		t.Errorf("expected 1 (no args), got %d", code)
	}
}
