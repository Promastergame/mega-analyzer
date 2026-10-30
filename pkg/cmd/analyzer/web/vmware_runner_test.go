package web

import (
	"strings"
	"testing"
	"time"
)

func TestVMwareExecutionRequestBindsDetectedIdentityAndParameters(t *testing.T) {
	s, vm, _ := vmwareTestServer(t)
	vm.OSType = "windows9-64"
	s.vmwareDiscover = func() []vmEntry { return []vmEntry{vm} }
	flags, err := validateSandboxRequest(vm.ID, "yes", "fixture.exe", "windows", []string{"-sandbox-duration", "0", "-sandbox-memory", "768", "-sandbox-cpu-cores", "2", "-sandbox-profile", "basic", "-sandbox-args", `--path "C:\A B"`})
	if err != nil {
		t.Fatal(err)
	}
	const password = " test-only-+$! "
	req, err := s.vmwareExecutionRequest(vm.ID, " guest-user ", password, "fixture.exe", flags)
	if err != nil {
		t.Fatal(err)
	}
	if req.Username != "guest-user" || req.Password != password || req.VMX != vm.ConfigPath || req.MemoryMB != 768 || req.CPUCores != 2 || req.Duration != time.Duration(0) || req.Args != `--path "C:\A B"` {
		t.Fatalf("wrong request: %+v", req)
	}
	if _, err := s.vmwareExecutionRequest("vmware:unknown", "guest-user", password, "fixture.exe", nil); err == nil {
		t.Fatal("unknown VM accepted")
	}
	for _, args := range [][]string{{"-sandbox-allow-net"}, {"-sandbox-allow-host-execution"}, {"-sandbox-frida"}, {"-sandbox-device", "host"}} {
		if _, err := validateSandboxRequest(vm.ID, "yes", "fixture.exe", "windows", args); err == nil {
			t.Fatalf("unsafe VMware flags accepted: %v", args)
		}
	}
	if !strings.Contains(webUIHTML, `isVMwareTarget()?curTarget.key:`) || !strings.Contains(webUIHTML, `fd.append("vmware-user"`) {
		t.Fatal("UI does not submit the detected VMware identity and guest username")
	}
}

func TestVMwareDesktopModeValidation(t *testing.T) {
	s, vm, _ := vmwareTestServer(t)
	vm.OSType = "windows9-64"
	s.vmwareDiscover = func() []vmEntry { return []vmEntry{vm} }
	for _, mode := range []string{"background", "interactive"} {
		flags, err := validateSandboxRequest(vm.ID, "yes", "fixture.exe", "windows", []string{"-sandbox-desktop", mode})
		if err != nil { t.Fatal(err) }
		req, err := s.vmwareExecutionRequest(vm.ID, "guest-user", "test-only", "fixture.exe", flags)
		if err != nil || req.Interactive != (mode == "interactive") { t.Fatalf("desktop mode lost: %s, %v", mode, err) }
	}
	if _, err := validateSandboxRequest(vm.ID, "yes", "fixture.exe", "windows", []string{"-sandbox-desktop", "invalid"}); err == nil {
		t.Fatal("invalid desktop mode accepted")
	}
	if _, err := validateSandboxRequest("device:emulator-5554", "yes", "fixture.apk", "windows", []string{"-sandbox-desktop", "interactive", "-sandbox-allow-net"}); err == nil {
		t.Fatal("VMware desktop mode accepted for Android")
	}
}
