package modules

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

func TestAllModuleContractsAndFailurePropagation(t *testing.T) {
	p := testProfile(t)
	p.Sensor.Enabled = true
	mods := []Module{NewIdentityModule(p), NewEnvironmentModule(p), NewBatteryModule(p), NewDisplayModule(p), NewLocaleModule(p), NewNetworkModule(p), NewSensorsModule(p), NewTelephonyModule(p)}
	for _, m := range mods {
		t.Run(m.Name(), func(t *testing.T) {
			if err := m.Validate(p); err != nil {
				t.Fatal(err)
			}
			ops := m.Plan(p)
			if len(ops) != 1 || ops[0].Name == "" || ops[0].Module != m.Name() || ops[0].Timeout <= 0 {
				t.Fatalf("plan=%+v", ops)
			}
			dev := adapter.NewMockAdapter()
			ctx := context.Background()
			res, err := m.Apply(ctx, dev)
			if err != nil || !res.OK() {
				t.Fatalf("apply=%+v %v", res, err)
			}
			for _, prop := range ops[0].Config.Props {
				if dev.State.Props[prop.Key] != prop.Value {
					t.Errorf("prop %s was not applied", prop.Key)
				}
			}
			if _, err := m.Verify(ctx, dev); err != nil {
				t.Fatal(err)
			}
			fail := errors.New("read failed")
			dev.ReadErr = fail
			if _, err := m.Verify(ctx, dev); !errors.Is(err, fail) {
				t.Fatalf("read failure swallowed: %v", err)
			}
			dev.ApplyErr = fail
			if _, err := m.Apply(ctx, dev); !errors.Is(err, fail) {
				t.Fatalf("apply failure swallowed: %v", err)
			}
		})
	}
}

func TestModuleValidationAndBatteryCommands(t *testing.T) {
	empty := profile.DeviceProfile{}
	for _, m := range []Module{NewIdentityModule(empty), NewDisplayModule(empty), NewLocaleModule(empty), NewNetworkModule(empty), NewTelephonyModule(empty)} {
		if err := m.Validate(empty); err == nil {
			t.Errorf("%s accepted missing fields", m.Name())
		}
	}
	p := testProfile(t)
	for _, tt := range []struct {
		level int
		bad   bool
	}{{-1, true}, {0, false}, {100, false}, {101, true}} {
		p.Battery.Level = tt.level
		if err := NewBatteryModule(p).Validate(p); (err != nil) != tt.bad {
			t.Errorf("battery level %d err=%v", tt.level, err)
		}
	}
	for _, tt := range []struct{ status, code string }{{"charging", "2"}, {"full", "5"}, {"discharging", "3"}, {"not-charging", "4"}} {
		p.Battery.Status = tt.status
		commands := NewBatteryModule(p).commands()
		if commands[2].Cmd != "dumpsys battery set status "+tt.code {
			t.Fatal(commands)
		}
	}
	p.Sensor.Enabled = false
	m := NewSensorsModule(p)
	if ops := m.Plan(p); len(ops) != 0 {
		t.Fatal("disabled sensors scheduled")
	}
	dev := adapter.NewMockAdapter()
	res, err := m.Apply(context.Background(), dev)
	if err != nil || len(res.Succeeded) != 0 || dev.ApplyCount != 0 {
		t.Fatal("disabled sensors executed")
	}
}

func TestBatteryAppliesCompleteProfile(t *testing.T) {
	p := testProfile(t)
	p.Battery = profile.BatteryProfile{Level: 71, Status: "charging", Temperature: 315, Health: "good", Plugged: "usb"}
	m := NewBatteryModule(p)
	if err := m.Validate(p); err != nil {
		t.Fatal(err)
	}
	want := []adapter.ShellCmd{{Cmd: "dumpsys battery unplug"}, {Cmd: "dumpsys battery set level 71"}, {Cmd: "dumpsys battery set status 2"}, {Cmd: "dumpsys battery set temp 315"}, {Cmd: "dumpsys battery set health 2"}, {Cmd: "dumpsys battery set usb 1"}}
	if !reflect.DeepEqual(m.commands(), want) {
		t.Fatalf("commands=%+v", m.commands())
	}
	for _, bad := range []profile.BatteryProfile{{Level: 71, Status: "broken"}, {Level: 71, Status: "charging", Health: "broken"}, {Level: 71, Status: "charging", Plugged: "broken"}} {
		p.Battery = bad
		if err := NewBatteryModule(p).Validate(p); err == nil {
			t.Fatalf("invalid battery profile accepted: %+v", bad)
		}
	}
}

func TestFilteredReportCountsMismatchesAndRollup(t *testing.T) {
	statuses := []verifier.Status{verifier.StatusPassed, verifier.StatusFailed, verifier.StatusSkipped, verifier.StatusPartial}
	full := verifier.Report{ByGroup: map[verifier.Group]verifier.Status{verifier.GroupBattery: verifier.StatusFailed, verifier.GroupBuild: verifier.StatusPassed}}
	for _, status := range statuses {
		full.Checks = append(full.Checks, verifier.Check{Group: verifier.GroupBattery, Status: status})
	}
	full.Checks = append(full.Checks, verifier.Check{Group: verifier.GroupBuild, Status: verifier.StatusPassed})
	got := filterReport(full, map[verifier.Group]bool{verifier.GroupBattery: true})
	if len(got.Checks) != 4 || len(got.Mismatches) != 1 || got.Counts.Passed != 1 || got.Counts.Failed != 1 || got.Counts.Partial != 1 || got.Counts.Skipped != 1 || got.Status != verifier.StatusFailed || !reflect.DeepEqual(got.ByGroup, map[verifier.Group]verifier.Status{verifier.GroupBattery: verifier.StatusFailed}) {
		t.Fatalf("filtered=%+v", got)
	}
	if rollup(verifier.Report{}) != verifier.StatusSkipped {
		t.Fatal("empty rollup")
	}
	for _, status := range []verifier.Status{verifier.StatusPassed, verifier.StatusSkipped, verifier.StatusPartial} {
		r := verifier.Report{Checks: []verifier.Check{{Status: status}}}
		want := verifier.StatusPassed
		if status == verifier.StatusSkipped {
			r.Counts.Skipped = 1
			want = verifier.StatusPartial
		}
		if status == verifier.StatusPartial {
			r.Counts.Partial = 1
			want = verifier.StatusPartial
		}
		if rollup(r) != want {
			t.Errorf("rollup %s", status)
		}
	}
}
