package vmware

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicitly opt-in: this test prepares, boots and shuts down the named VM.
// The caller supplies a trusted fixture. Normal test runs never touch a VM.
func TestVMwareLocalSmoke(t *testing.T) {
	vmx := os.Getenv("MEGA_VMWARE_TEST_VMX")
	if vmx == "" {
		t.Skip("opt-in local VMware integration test")
	}
	for _, name := range []string{"MEGA_VMWARE_TEST_TOOL", "MEGA_VMWARE_TEST_USER", "MEGA_VMWARE_TEST_COLLECTOR", "MEGA_VMWARE_TEST_SAMPLE", "MEGA_VMWARE_TEST_OUTPUT"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required", name)
		}
	}
	output := os.Getenv("MEGA_VMWARE_TEST_OUTPUT")
	manager := New(ExecRunner(os.Getenv("MEGA_VMWARE_TEST_TOOL")), filepath.Join(output, "baselines"))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	report, err := manager.Prepare(ctx, vmx)
	if err != nil || !report.ConfigurationPass {
		t.Fatalf("prepare: %+v, %v", report, err)
	}
	t.Log("VM configuration prepared; original VMX backup retained")
	for _, mode := range []string{"exit", "stop"} {
		t.Run(mode, func(t *testing.T) {
			runCtx, stop := context.WithCancel(ctx)
			defer stop()
			args := ""
			if mode == "stop" {
				args = "wait"
			}
			req := ExecutionRequest{VMX: vmx, Name: "Windows 10 x64", Username: os.Getenv("MEGA_VMWARE_TEST_USER"), Password: os.Getenv("MEGA_VMWARE_TEST_PASSWORD"), CollectorPath: os.Getenv("MEGA_VMWARE_TEST_COLLECTOR"), SamplePath: os.Getenv("MEGA_VMWARE_TEST_SAMPLE"), OutputDir: output, MemoryMB: 512, CPUCores: 2, Duration: 0, Args: args}
			if mode == "exit" {
				req.Duration = 5 * time.Second
			}
			result, err := manager.RunSession(runCtx, req, func(event Event) {
				if event.Type == "status" || event.Type == "report" {
					t.Log(event.Type, event.Stage, event.Details)
				}
				if mode == "stop" && event.Stage == "observing" {
					stop()
				}
			})
			if err != nil && !(mode == "stop" && errors.Is(err, context.Canceled)) {
				t.Fatalf("run: %v", err)
			}
			if result == nil || !result.Executed || !result.VMware.PoweredOff || result.VMware.Incomplete {
				t.Fatalf("incomplete guest execution: %+v", result)
			}
			stdout, err := os.ReadFile(result.StdoutPath)
			if err != nil || !strings.Contains(string(stdout), "MEGA_VMWARE_SMOKE") {
				t.Fatalf("guest output missing: %v", err)
			}
			if result.NetworkMode != "vmware_disconnected" || !result.NetworkGuardApplied {
				t.Fatalf("unexpected network boundary: %s", result.NetworkMode)
			}
			t.Log("Host report:", result.JSONPath)
		})
		if t.Failed() {
			break
		}
	}
}
