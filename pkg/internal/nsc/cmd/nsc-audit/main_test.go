package main

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/nsc"
	"mega-analyzer/pkg/internal/testutil"
)

func commandOutput(t *testing.T, args ...string) string {
	t.Helper()
	oldFlags, oldArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	flag.CommandLine = flag.NewFlagSet("nsc-audit-test", flag.ContinueOnError)
	os.Args = append([]string{"nsc-audit"}, args...)
	return testutil.CaptureStdout(t, main)
}

func TestCommandReports(t *testing.T) {
	root := testutil.TempDir(t)
	path := filepath.Join(root, "nsc.xml")
	const safe = `<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/></trust-anchors></base-config></network-security-config>`
	if err := os.WriteFile(path, []byte(safe), 0600); err != nil {
		t.Fatal(err)
	}
	out := commandOutput(t, "-json", "-strict", "-target", "fixture-app", path)
	var report nsc.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Present || report.Target != "fixture-app" || report.Verdict == "weak" || report.Verdict == "dangerous" {
		t.Fatalf("report=%+v", report)
	}
	markdown := commandOutput(t, path)
	if !strings.Contains(markdown, "# Network Security Config Audit") || !strings.Contains(markdown, path) {
		t.Fatal(markdown)
	}
	out = commandOutput(t, "-json", testutil.TempDir(t))
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Present || report.Verdict != "absent" {
		t.Fatalf("empty dir=%+v", report)
	}
}

// os.Exit paths run in an isolated copy of this test executable. No external
// compiler invocation, shell or installed nsc-audit binary is required.
func TestCommandExitCodes(t *testing.T) {
	if os.Getenv("MEGA_NSC_TEST_CHILD") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				flag.CommandLine = flag.NewFlagSet("nsc-child", flag.ContinueOnError)
				os.Args = append([]string{"nsc-audit"}, os.Args[i+1:]...)
				main()
				return
			}
		}
		t.Fatal("missing argument separator")
	}
	root := testutil.TempDir(t)
	bad := filepath.Join(root, "bad.xml")
	weak := filepath.Join(root, "weak.xml")
	if err := os.WriteFile(bad, []byte("<broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(weak, []byte(`<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		args []string
		code int
		part string
	}{
		{"usage", nil, 64, "usage:"}, {"missing", []string{bad + ".missing"}, 66, "nsc-audit:"}, {"invalid", []string{bad}, 65, "nsc-audit:"}, {"strict", []string{"-strict", weak}, 2, "Network Security Config Audit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestCommandExitCodes$", "--"}, tt.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "MEGA_NSC_TEST_CHILD=1")
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != tt.code {
				t.Fatalf("exit=%v output=%s want code %d", err, out, tt.code)
			}
			if !strings.Contains(string(out), tt.part) {
				t.Fatalf("output=%s want %s", out, tt.part)
			}
		})
	}
}
