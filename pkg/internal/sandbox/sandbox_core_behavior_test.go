package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunValidatesConfigBeforePlatformSupport(t *testing.T) {
	if _, err := Run(context.Background(), Config{}); err == nil || !strings.Contains(err.Error(), "target path is required") {
		t.Fatalf("Run with empty config error = %v, want target validation error", err)
	}

	target := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(target, []byte("sample"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), Config{TargetPath: target, Duration: 5 * time.Second, MaxMemoryMB: 128})
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("Run on Windows returned unexpected early error: %v", err)
		}
		return
	}
	// Off Windows the sample cannot be executed natively, but Run must still
	// complete and say so in the report. Returning an error up front (the old
	// behaviour this test used to assert) made the entire Android detonation
	// path unreachable on Linux and macOS, since the check ran before dispatch.
	if err != nil {
		t.Fatalf("Run on non-Windows error = %v, want a completed report", err)
	}
	if rep == nil {
		t.Fatal("Run on non-Windows returned no report")
	}
	if rep.Executed {
		t.Error("report.Executed = true off Windows, want false")
	}
	if !strings.Contains(rep.ExecutionSkipReason, "requires Windows") {
		t.Errorf("ExecutionSkipReason = %q, want it to name the Windows requirement", rep.ExecutionSkipReason)
	}
}

func TestPrepareSessionLayoutCreatesIsolatedTree(t *testing.T) {
	layout, err := prepareSessionLayout(t.TempDir())
	if err != nil {
		t.Fatalf("prepareSessionLayout returned error: %v", err)
	}

	paths := []string{
		layout.sessionDir,
		layout.workspaceDir,
		layout.profileDir,
		layout.tempDir,
		layout.homeDir,
		layout.appDataDir,
		layout.localAppData,
		layout.programData,
		layout.publicDir,
		filepath.Join(layout.homeDir, "Desktop"),
		filepath.Join(layout.homeDir, "Documents"),
		filepath.Join(layout.homeDir, "Downloads"),
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected sandbox path %s to exist: %v", path, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected sandbox path %s to be a directory", path)
		}
	}
	if !strings.HasSuffix(layout.jsonPath, "sandbox_report.json") {
		t.Fatalf("json path = %q, want sandbox_report.json", layout.jsonPath)
	}
	if !strings.HasSuffix(layout.markdownPath, "sandbox_report.md") {
		t.Fatalf("markdown path = %q, want sandbox_report.md", layout.markdownPath)
	}
}

func TestPrepareLaunchSpecCopiesTargetsAndClassifiesRunnableFiles(t *testing.T) {
	layout, err := prepareSessionLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ext        string
		runnable   bool
		wantPrefix []string
	}{
		{name: "exe", ext: ".exe", runnable: true},
		{name: "cmd", ext: ".cmd", runnable: true, wantPrefix: []string{"/c"}},
		{name: "powershell", ext: ".ps1", runnable: true, wantPrefix: []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File"}},
		{name: "static", ext: ".txt", runnable: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "sample"+tt.ext)
			content := []byte("payload")
			if err := os.WriteFile(target, content, 0o640); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}

			spec, err := prepareLaunchSpec(target, info, layout, `--flag "two words"`)
			if err != nil {
				t.Fatalf("prepareLaunchSpec returned error: %v", err)
			}
			if spec.runnable != tt.runnable {
				t.Fatalf("runnable = %v, want %v", spec.runnable, tt.runnable)
			}
			if spec.copiedPath == "" {
				t.Fatal("expected target to be copied into workspace")
			}
			copied, err := os.ReadFile(spec.copiedPath)
			if err != nil {
				t.Fatalf("read copied target: %v", err)
			}
			if string(copied) != string(content) {
				t.Fatalf("copied content = %q, want %q", copied, content)
			}
			for i, want := range tt.wantPrefix {
				if len(spec.args) <= i || spec.args[i] != want {
					t.Fatalf("args prefix = %v, want %v", spec.args, tt.wantPrefix)
				}
			}
			if tt.runnable && len(tt.wantPrefix) == 0 && spec.executable != spec.copiedPath {
				t.Fatalf("executable = %q, want copied target %q", spec.executable, spec.copiedPath)
			}
			if !tt.runnable && !strings.Contains(spec.reason, "static inspection") {
				t.Fatalf("static skip reason = %q", spec.reason)
			}
		})
	}
}

func TestSandboxEnvironmentAndPermissionsAreDerivedFromLayout(t *testing.T) {
	layout, err := prepareSessionLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	env := minimalEnvironment(layout)
	for _, want := range []string{
		"TEMP=" + layout.tempDir,
		"TMP=" + layout.tempDir,
		"USERPROFILE=" + layout.homeDir,
		"APPDATA=" + layout.appDataDir,
		"LOCALAPPDATA=" + layout.localAppData,
		"ProgramData=" + layout.programData,
		"PUBLIC=" + layout.publicDir,
		"MEGA_ANALYZER_SANDBOX=1",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
	} {
		if !containsString(env, want) {
			t.Fatalf("minimalEnvironment missing %q in %v", want, env)
		}
	}

	permissions := buildSandboxPermissions(Config{BlockNetwork: true, MaxMemoryMB: 768}, layout)
	if permissions.NetworkAccess != "blocked" {
		t.Fatalf("network access = %q, want blocked", permissions.NetworkAccess)
	}
	if permissions.MaxMemoryMB != 768 {
		t.Fatalf("max memory = %d, want 768", permissions.MaxMemoryMB)
	}
	for _, want := range []string{layout.workspaceDir, layout.tempDir, layout.homeDir, layout.appDataDir, layout.localAppData, layout.programData, layout.publicDir} {
		if !containsString(permissions.ExposedWritePaths, want) {
			t.Fatalf("permissions missing exposed path %q", want)
		}
	}
}

func TestCaptureFileSnapshotHashAndDiff(t *testing.T) {
	root := t.TempDir()
	stable := filepath.Join(root, "stable.txt")
	modified := filepath.Join(root, "modified.txt")
	deleted := filepath.Join(root, "deleted.txt")
	for path, content := range map[string]string{stable: "same", modified: "before", deleted: "gone"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	before, err := captureFileSnapshot(root)
	if err != nil {
		t.Fatalf("capture before: %v", err)
	}
	if err := os.WriteFile(modified, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(root, "created.txt")
	if err := os.WriteFile(created, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := captureFileSnapshot(root)
	if err != nil {
		t.Fatalf("capture after: %v", err)
	}
	changes := diffSnapshots(before, after)
	if len(changes.Created) != 1 || changes.Created[0].Path != "created.txt" {
		t.Fatalf("created changes = %+v", changes.Created)
	}
	if len(changes.Modified) != 1 || changes.Modified[0].Path != "modified.txt" {
		t.Fatalf("modified changes = %+v", changes.Modified)
	}
	if len(changes.Deleted) != 1 || changes.Deleted[0].Path != "deleted.txt" {
		t.Fatalf("deleted changes = %+v", changes.Deleted)
	}
	if before["stable.txt"].SHA256 == "" || before["stable.txt"].Size != int64(len("same")) {
		t.Fatalf("stable fingerprint = %+v", before["stable.txt"])
	}
}

func TestWriteReportsPersistsJSONAndMarkdown(t *testing.T) {
	layout, err := prepareSessionLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	report := &Report{
		SessionID:      filepath.Base(layout.sessionDir),
		TargetOriginal: filepath.Join(layout.workspaceDir, "sample.exe"),
		TargetCopied:   filepath.Join(layout.workspaceDir, "sample.exe"),
		InputType:      "exe",
		WorkspaceDir:   layout.workspaceDir,
		JSONPath:       layout.jsonPath,
		MarkdownPath:   layout.markdownPath,
		StartedAt:      now,
		FinishedAt:     now.Add(time.Second),
		DurationMS:     int64(time.Second / time.Millisecond),
		Behavior: BehaviorSummary{
			Highlights:       []string{"network"},
			ConnectionCount:  1,
			CreatedFileCount: 1,
			PersistenceCount: 1,
		},
		Warnings: []string{"warning"},
	}

	if err := writeReports(report); err != nil {
		t.Fatalf("writeReports returned error: %v", err)
	}
	jsonData, err := os.ReadFile(layout.jsonPath)
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	if !strings.Contains(string(jsonData), `"session_id"`) || !strings.Contains(string(jsonData), report.SessionID) {
		t.Fatalf("JSON report missing session data: %s", jsonData)
	}
	markdown, err := os.ReadFile(layout.markdownPath)
	if err != nil {
		t.Fatalf("read markdown report: %v", err)
	}
	if !strings.Contains(string(markdown), "# Sandbox Report") || !strings.Contains(string(markdown), "warning") {
		t.Fatalf("markdown report missing expected content: %s", markdown)
	}
}
