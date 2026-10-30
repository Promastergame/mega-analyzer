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

	// No mode specified
	code = run([]string{})
	if code != 1 {
		t.Errorf("expected 1 when no mode specified, got %d", code)
	}

	// Multiple modes
	code = run([]string{"--target", "http://example.com", "--html-body", "index.html"})
	if code != 1 {
		t.Errorf("expected 1 for multiple modes, got %d", code)
	}

	// HTML body mode failure
	code = run([]string{"--html-body", "nonexistent.html"})
	if code != 1 {
		t.Errorf("expected 1 for nonexistent html body, got %d", code)
	}

	// Active mode needs permission
	code = run([]string{"--target", "http://example.com"})
	if code != 1 {
		t.Errorf("expected 1 without i-own-this-target, got %d", code)
	}

	code = run([]string{"--curl", "curl http://example.com"})
	if code != 1 {
		t.Errorf("expected 1 without i-own-this-target, got %d", code)
	}

	code = run([]string{"--raw-request", "req.txt"})
	if code != 1 {
		t.Errorf("expected 1 without i-own-this-target, got %d", code)
	}

	// Raw Request failures
	code = run([]string{"--raw-request", "nonexistent.txt", "--i-own-this-target"})
	if code != 1 {
		t.Errorf("expected 1 for nonexistent raw request, got %d", code)
	}
}
