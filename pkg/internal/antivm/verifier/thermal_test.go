package verifier

import (
	"testing"

	"mega-analyzer/pkg/internal/antivm/adapter"
)

func TestDisabledSensorsDoNotRequireThermalReading(t *testing.T) {
	p := sampleProfile(t)
	p.Sensor.Enabled = false
	st := stateMatching(p)
	st.Sensors[adapter.ThermalTemperatureKey] = "0"
	rep := Verify(p, st, criticals)
	if _, exists := rep.ByGroup[GroupSensors]; exists || rep.Status != StatusPassed {
		t.Fatalf("disabled sensors were checked: %+v", rep)
	}
}

func TestStaticSensorEventsFailVerification(t *testing.T) {
	p := sampleProfile(t)
	st := stateMatching(p)
	st.Sensors["acceleration.moving"] = "false"
	rep := Verify(p, st, criticals)
	if rep.ByGroup[GroupSensors] != StatusFailed || rep.Status != StatusPartial {
		t.Fatalf("static events accepted: %+v", rep)
	}
}
