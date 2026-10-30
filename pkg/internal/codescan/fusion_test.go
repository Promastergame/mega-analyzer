package codescan

import (
	"testing"
)

func TestCodescanFusionIntegration(t *testing.T) {
	jsCode := `
		const apiKey = "AKIA1234567890123456";
		eval(atob("YWxlcnQoMSk="));
	`
	res := Scan("test.js", "javascript", []byte(jsCode))

	if res.FusionIntelligence == nil {
		t.Fatal("expected non-nil FusionIntelligence attached to codescan Result")
	}

	fi := res.FusionIntelligence
	if fi.SampleID == "" {
		t.Error("expected sample ID in fusion report")
	}
	if fi.Decision.Explanation == "" {
		t.Error("expected explanation in fusion report")
	}
}
