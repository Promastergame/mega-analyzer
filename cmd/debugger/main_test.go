package main

import (
	"testing"
)

func TestRun(t *testing.T) {
	code := run([]string{"-test-run-only"})
	if code != 0 {
		t.Errorf("expected 0, got %d", code)
	}

	code = run([]string{"-invalidflag"})
	if code != 1 {
		t.Errorf("expected 1, got %d", code)
	}

	code = run([]string{})
	if code != 1 {
		t.Errorf("expected 1 when no command provided, got %d", code)
	}

	code = run([]string{"start"})
	if code != 1 {
		t.Errorf("expected 1 for start without -file, got %d", code)
	}

	code = run([]string{"step"})
	if code != 1 {
		t.Errorf("expected 1 for step without session, got %d", code)
	}

	code = run([]string{"continue"})
	if code != 1 {
		t.Errorf("expected 1 for continue without session, got %d", code)
	}

	code = run([]string{"regs"})
	if code != 1 {
		t.Errorf("expected 1 for regs without session, got %d", code)
	}
}
