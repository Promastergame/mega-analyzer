package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestADBArgumentsAndUnavailableTransport(t *testing.T) {
	a := NewADBAdapter(filepath.Join(t.TempDir(), "missing-adb"), "emulator-5554")
	if a.BootTimeout != 120*time.Second || !reflect.DeepEqual(a.args("shell", "getprop"), []string{"-s", "emulator-5554", "shell", "getprop"}) {
		t.Fatal("ADB defaults/serial routing")
	}
	a.Serial = ""
	if !reflect.DeepEqual(a.args("devices"), []string{"devices"}) {
		t.Fatal("default device args")
	}
	ctx := context.Background()
	if err := a.Start(ctx); err == nil || !strings.Contains(err.Error(), "get-state") {
		t.Fatalf("start=%v", err)
	}
	if _, err := a.ReadState(ctx); err == nil || !strings.Contains(err.Error(), "read props") {
		t.Fatalf("read=%v", err)
	}
	if ev, err := a.CollectEvidence(ctx); err == nil || ev.Collected {
		t.Fatalf("evidence=%+v %v", ev, err)
	}
	res, err := a.ApplyTestConfig(ctx, TestConfig{Props: []PropSet{{Key: "ro.test", Value: "value"}}, Commands: []ShellCmd{{Cmd: "wm size"}}})
	if err != nil || res.OK() || len(res.Failed) != 2 || len(res.Succeeded) != 0 {
		t.Fatalf("per-command failures=%+v %v", res, err)
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := a.WaitForBoot(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	a.BootTimeout = time.Nanosecond
	if err := a.WaitForBoot(ctx); err == nil || !strings.Contains(err.Error(), "boot timeout") {
		t.Fatalf("timeout=%v", err)
	}
}

func TestMockFailureContracts(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("injected failure")
	m := NewMockAdapter()
	m.BootErr = boom
	if err := m.WaitForBoot(ctx); !errors.Is(err, boom) || m.Booted {
		t.Fatal("boot failure swallowed")
	}
	m.ApplyErr = boom
	if _, err := m.ApplyTestConfig(ctx, TestConfig{}); !errors.Is(err, boom) || m.ApplyCount != 1 {
		t.Fatal("apply failure/count")
	}
	m.EvidenceErr = boom
	if _, err := m.CollectEvidence(ctx); !errors.Is(err, boom) {
		t.Fatal("evidence failure swallowed")
	}
	m.StopErr = boom
	if err := m.Stop(ctx); !errors.Is(err, boom) || m.Stopped {
		t.Fatal("stop failure swallowed")
	}
	m.EvidenceErr = nil
	ev, err := m.CollectEvidence(ctx)
	if err != nil || !ev.Collected {
		t.Fatal("evidence success")
	}
	m.ApplyErr = nil
	m.State.Props = nil
	res, err := m.ApplyTestConfig(ctx, TestConfig{Props: []PropSet{{Key: "x", Value: "y"}}, Commands: []ShellCmd{{Cmd: "echo test"}}})
	if err != nil || !res.OK() || len(res.Succeeded) != 2 || m.State.Props["x"] != "y" {
		t.Fatalf("nil maps=%+v %v", res, err)
	}
	for _, s := range []string{"4", "not charging", "not-charging"} {
		if normalizeBatteryStatus(s) != "not-charging" {
			t.Error(s)
		}
	}
	if got := parseDumpsysBattery("ignored\nunknown: value\nUSB powered: false"); got["plugged"] != "none" {
		t.Fatal(got)
	}
}
