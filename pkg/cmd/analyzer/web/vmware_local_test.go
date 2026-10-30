package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVMwareLocalDiscovery(t *testing.T) {
	expected := os.Getenv("MEGA_VMWARE_TEST_VMX")
	if expected == "" {
		t.Skip("opt-in discovery of a registered local VM")
	}
	path, _, ok := readVMXDefinition(expected)
	if !ok {
		_, linkErr := filepath.EvalSymlinks(expected)
		_, readErr := readSmallVMFile(expected)
		t.Fatalf("local VM definition unreadable: symlinks=%v, read=%v", linkErr, readErr)
	}
	for _, vm := range detectVMwareVMs() {
		if strings.EqualFold(vm.ConfigPath, path) && vm.Registered {
			t.Log("Registered target:", vm.Name, vm.ID)
			return
		}
	}
	t.Fatalf("VM %s missing from discovery; APPDATA=%s", path, os.Getenv("APPDATA"))
}
