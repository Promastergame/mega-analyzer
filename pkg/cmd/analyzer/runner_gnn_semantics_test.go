package main

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestGNNLicenseSemanticsRequireIndependentEvidence(t *testing.T) {
	cases := []struct {
		name   string
		method types.SmaliMethod
		want   bool
	}{
		{"UI branch", types.SmaliMethod{Name: "setTint", Conditions: []types.Condition{{}}}, false},
		{"collection mutation", types.SmaliMethod{Name: "removeRange", Conditions: []types.Condition{{}}, Invokes: []types.Invoke{{Class: "java.util.ArrayList", Method: "remove"}}}, false},
		{"license name only", types.SmaliMethod{Name: "checkLicense", Conditions: []types.Condition{{}}}, false},
		{"protocol constant only", types.SmaliMethod{StringConsts: []types.StringConstant{{Value: "INAPP_DATA_SIGNATURE"}}}, false},
		{"LVL API", types.SmaliMethod{Invokes: []types.Invoke{{Class: "Lcom/google/android/vending/licensing/LicenseChecker;", Method: "checkAccess"}}}, true},
		{"signature validation of purchase", types.SmaliMethod{StringConsts: []types.StringConstant{{Value: "INAPP_DATA_SIGNATURE"}}, Invokes: []types.Invoke{{Class: "java.security.Signature", Method: "verify"}}}, true},
		{"obfuscated purchase gate", types.SmaliMethod{Name: "a", StringConsts: []types.StringConstant{{Value: "INAPP_PURCHASE_DATA"}}, Conditions: []types.Condition{{}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gnnDirectLicenseEvidence(&tc.method) != ""; got != tc.want {
				t.Fatalf("corroborated=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestGNNLicenseWrapperDoesNotLabelUnrelatedConstructor(t *testing.T) {
	files := map[string]*types.FileAnalysis{"a": {SmaliClass: &types.SmaliClass{Name: "Lapp/a;", Methods: []types.SmaliMethod{
		{Name: "verify", ReturnType: "Z", Invokes: []types.Invoke{{Class: "com.google.android.vending.licensing.LicenseChecker", Method: "checkAccess"}}},
		{Name: "gate", ReturnType: "V", Conditions: []types.Condition{{}}, Invokes: []types.Invoke{{Class: "Lapp/a;", Method: "verify", ReturnType: "Z"}}},
		{Name: "<init>", ReturnType: "V", Invokes: []types.Invoke{{Class: "Lapp/a;", Method: "verify", ReturnType: "Z"}}},
	}}}}
	index := gnnLicenseEvidence(files)
	if index["Lapp/a;->gate()V"] == "" || index["Lapp/a;->verify()Z"] == "" || index["Lapp/a;-><init>()V"] != "" {
		t.Fatalf("unexpected corroboration: %+v", index)
	}
}
