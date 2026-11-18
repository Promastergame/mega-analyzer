package s1

import "testing"

func TestCalibrationBindsConfigurationAndInvalidatesChanges(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	e.ModelFingerprint = "test-weights-v1"
	c := DefaultCalibration()
	c.Fitted = map[string]int{TypeChoice: 100}
	var err error
	c, err = e.BindCalibration(c)
	if err != nil {
		t.Fatal(err)
	}
	e.Calib = c
	if e.CalibrationIssue() != "" {
		t.Fatal(e.CalibrationIssue())
	}
	e.NoLex = true
	if e.CalibrationIssue() != "configuration_mismatch" {
		t.Fatal("fusion change accepted")
	}
	e.NoLex = false
	e.ModelFingerprint = "test-weights-v2"
	if e.CalibrationIssue() != "configuration_mismatch" {
		t.Fatal("weight change accepted")
	}
	e.ModelFingerprint = "test-weights-v1"
	e.Calib.Fingerprint = ""
	if e.CalibrationIssue() != "legacy_calibration_unbound" {
		t.Fatal("legacy calibration accepted")
	}
	e.ModelFingerprint = ""
	if _, err = e.BindCalibration(c); err == nil {
		t.Fatal("bound unidentified model")
	}
}
func TestCalibrationIdentityCapsNeuralAuto(t *testing.T) {
	e := NewEngine(&orchard{}, DefaultCalibration())
	e.NoLex = true
	e.ModelFingerprint = "orchard-v1"
	e.Calib.Temps[TypeChoice] = .1
	e.Calib.Fitted = map[string]int{TypeChoice: 100}
	r := req(t, `{"state":"Fresh fruit from the orchard.","questions":{"q":{"type":"choice","instructions":"pick","criteria":{"fruit":"Fresh fruit from the orchard","vehicle":"Road vehicles for transport"}}}}`)
	unbound, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if unbound.Answers["q"].Route == "auto" {
		t.Fatal("unbound model acted automatically")
	}
	e.Calib.Fingerprint = e.ConfigurationFingerprint()
	bound, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Answers["q"].Route != "auto" {
		t.Fatalf("bound route: %+v", bound.Answers["q"])
	}
	e.MaxChunks++
	changed, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Answers["q"].Route == "auto" {
		t.Fatal("changed retrieval acted automatically")
	}
}
