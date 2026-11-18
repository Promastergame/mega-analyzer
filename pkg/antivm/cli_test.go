package antivm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(name string) string {
	return filepath.Join("..", "internal", "antivm", "profiles", name)
}

func TestRunVerifyPersistsUnmodifiedReplay(t *testing.T) {
	dir := t.TempDir()
	replay := filepath.Join(dir, "capture.json")
	if err := os.WriteFile(replay, []byte(`{"props":{"ro.product.model":"sdk_gphone64","ro.kernel.qemu":"1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(dir, "sessions")
	if code := Run([]string{"session", "verify", "--profile", fixture("pixel-8-api-35.json"), "--replay", replay, "--sessions", sessions, "--report", "json"}); code != 1 {
		t.Fatalf("mismatching replay returned %d", code)
	}
	entries, err := os.ReadDir(sessions)
	if err != nil || len(entries) != 1 {
		t.Fatalf("sessions=%v, %v", entries, err)
	}
	before, err := os.ReadFile(filepath.Join(sessions, entries[0].Name(), "before.json"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(sessions, entries[0].Name(), "after.json"))
	if err != nil || string(before) != string(after) {
		t.Fatalf("verification changed the capture: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(sessions, entries[0].Name(), "verification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		VerifyOnly bool `json:"verify_only"`
	}
	if err := json.Unmarshal(data, &report); err != nil || !report.VerifyOnly {
		t.Fatalf("missing verify-only evidence: %s, %v", data, err)
	}
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

func TestRunSessionSupportsThermalSensorsModule(t *testing.T) {
	dir := t.TempDir()
	code := Run([]string{"session", "start", "--profile", fixture("pixel-8-avd-api-35.json"),
		"--mock", "--module", "sensors", "--sessions", dir, "--report", "json"})
	if code != 0 {
		t.Fatalf("sensors module returned %d", code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("sessions=%v err=%v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name(), "verification.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Status  string `json:"status"`
		Modules []struct {
			Module string `json:"module"`
		} `json:"modules"`
		Operations []struct {
			Name string `json:"name"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "partial" || len(report.Modules) != 1 || report.Modules[0].Module != "sensors" || len(report.Operations) != 1 || report.Operations[0].Name != "sensors.thermal" {
		t.Fatalf("unexpected thermal session: %s", data)
	}
}

func TestRun_SessionVerify_RequiresSource(t *testing.T) {
	// session verify without --replay/--mock is an error.
	code := Run([]string{"session", "verify", "--profile", fixture("pixel-7-api-34.json")})
	if code != 1 {
		t.Errorf("verify without source returned %d, want 1", code)
	}
}

func TestRun_SessionStart_RejectsUnknownModulesBeforeCreatingArtifacts(t *testing.T) {
	for _, filter := range []string{"identty", "identity,missing", "environment,battery,locale"} {
		t.Run(filter, func(t *testing.T) {
			dir := t.TempDir()
			code := Run([]string{"session", "start", "--profile", fixture("pixel-8-api-35.json"),
				"--mock", "--module", filter, "--sessions", dir})
			if code != 2 {
				t.Fatalf("unknown module returned %d, want usage error 2", code)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid module created session artifacts: %v, %v", entries, err)
			}
		})
	}
}
