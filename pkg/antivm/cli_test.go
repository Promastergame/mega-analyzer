package antivm

import (
	"path/filepath"
	"testing"
)

func fixture(name string) string {
	return filepath.Join("..", "internal", "antivm", "profiles", name)
}

func TestRun_TestGate(t *testing.T) {
	if code := Run([]string{"-test-run-only"}); code != 0 {
		t.Errorf("test gate returned %d, want 0", code)
	}
}

func TestRun_NoArgs(t *testing.T) {
	if code := Run(nil); code != 2 {
		t.Errorf("no args returned %d, want 2", code)
	}
}

func TestRun_Help(t *testing.T) {
	if code := Run([]string{"help"}); code != 0 {
		t.Errorf("help returned %d, want 0", code)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	if code := Run([]string{"frobnicate"}); code != 2 {
		t.Errorf("unknown command returned %d, want 2", code)
	}
}

func TestRun_ProfileValidate_Good(t *testing.T) {
	code := Run([]string{"profile", "validate", fixture("pixel-7-api-34.json")})
	if code != 0 {
		t.Errorf("validate good profile returned %d, want 0", code)
	}
}

func TestRun_ProfileValidate_Missing(t *testing.T) {
	code := Run([]string{"profile", "validate", "does-not-exist.json"})
	if code != 1 {
		t.Errorf("validate missing returned %d, want 1", code)
	}
}

func TestRun_SessionStart_Mock_DryRun(t *testing.T) {
	// Dry run against a fixture: plans, does not apply, exits 0.
	code := Run([]string{
		"session", "start",
		"--profile", fixture("pixel-8-api-35.json"),
		"--mock", "--dry-run",
		"--report", "text",
	})
	if code != 0 {
		t.Errorf("dry-run session returned %d, want 0", code)
	}
}

func TestRun_SessionStart_Mock(t *testing.T) {
	dir := t.TempDir()
	// Full mock run: identity+environment pass, battery skipped → overall
	// partial (not failed), exit 0.
	code := Run([]string{
		"session", "start",
		"--profile", fixture("pixel-9-api-36.json"),
		"--mock",
		"--sessions", dir,
		"--report", "json",
	})
	if code != 0 {
		t.Errorf("mock session returned %d, want 0", code)
	}
}

func TestRun_SessionStart_MissingProfile(t *testing.T) {
	code := Run([]string{"session", "start", "--mock"})
	if code != 2 {
		t.Errorf("missing --profile returned %d, want 2", code)
	}
}

func TestRun_SessionVerify_RequiresSource(t *testing.T) {
	// session verify without --replay/--mock is an error.
	code := Run([]string{"session", "verify", "--profile", fixture("pixel-7-api-34.json")})
	if code != 1 {
		t.Errorf("verify without source returned %d, want 1", code)
	}
}
