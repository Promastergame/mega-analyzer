package adapter

import (
	"context"
	"errors"
	"testing"
)

func TestParseWMSize(t *testing.T) {
	cases := map[string]string{
		"Physical size: 1080x2400":                           "1080x2400",
		"Physical size: 1440x3120\nOverride size: 1080x2400": "1080x2400",
		"garbage": "",
	}
	for in, want := range cases {
		if got := parseWMSize(in); got != want {
			t.Errorf("parseWMSize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWMDensity(t *testing.T) {
	if got := parseWMDensity("Physical density: 420"); got != "420" {
		t.Errorf("got %q, want 420", got)
	}
	if got := parseWMDensity("Physical density: 560\nOverride density: 480"); got != "480" {
		t.Errorf("got %q, want 480 (override)", got)
	}
}

func TestParseDumpsysBattery(t *testing.T) {
	out := `Current Battery Service state:
  AC powered: false
  USB powered: true
  level: 73
  status: 2
  health: 2
  temperature: 315`
	m := parseDumpsysBattery(out)
	if m["level"] != "73" {
		t.Errorf("level = %q", m["level"])
	}
	if m["status"] != "charging" {
		t.Errorf("status = %q, want charging", m["status"])
	}
	if m["plugged"] != "usb" {
		t.Errorf("plugged = %q, want usb", m["plugged"])
	}
	if m["temperature"] != "315" {
		t.Errorf("temperature = %q", m["temperature"])
	}
}

func TestNormalizeBatteryStatus(t *testing.T) {
	cases := map[string]string{
		"2": "charging", "3": "discharging", "5": "full",
		"Discharging": "discharging", "weird": "unknown",
	}
	for in, want := range cases {
		if got := normalizeBatteryStatus(in); got != want {
			t.Errorf("normalizeBatteryStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMockAdapter_ApplyReflectsProps(t *testing.T) {
	m := NewMockAdapter()
	ctx := context.Background()
	res, err := m.ApplyTestConfig(ctx, TestConfig{
		Props: []PropSet{{"ro.product.model", "Pixel 7"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("expected all succeeded, got %+v", res.Failed)
	}
	st, _ := m.ReadState(ctx)
	if st.Props["ro.product.model"] != "Pixel 7" {
		t.Errorf("apply did not reflect into state: %v", st.Props)
	}
}

func TestMockAdapter_FailProps(t *testing.T) {
	m := NewMockAdapter()
	m.FailProps = map[string]bool{"ro.secure": true}
	res, err := m.ApplyTestConfig(context.Background(), TestConfig{
		Props: []PropSet{{"ro.secure", "1"}, {"ro.debuggable", "0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Error("expected a per-command failure")
	}
	if len(res.Succeeded) != 1 || len(res.Failed) != 1 {
		t.Errorf("got succeeded=%v failed=%v", res.Succeeded, res.Failed)
	}
}

func TestMockAdapter_InjectedErrors(t *testing.T) {
	m := NewMockAdapter()
	m.StartErr = errors.New("boom")
	if err := m.Start(context.Background()); err == nil {
		t.Error("expected Start error")
	}
	m2 := NewMockAdapter()
	m2.ReadErr = errors.New("read fail")
	if _, err := m2.ReadState(context.Background()); err == nil {
		t.Error("expected ReadState error")
	}
}

func TestMockAdapter_Lifecycle(t *testing.T) {
	m := NewMockAdapter()
	ctx := context.Background()
	_ = m.Start(ctx)
	_ = m.WaitForBoot(ctx)
	_ = m.Stop(ctx)
	if !m.Started || !m.Booted || !m.Stopped {
		t.Errorf("lifecycle flags not set: %s", m)
	}
}
