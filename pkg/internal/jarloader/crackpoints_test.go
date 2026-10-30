package jarloader

import (
	"testing"

	"mega-analyzer/pkg/internal/crackpoint"
)

func TestDetectCrackPoints_JAR(t *testing.T) {
	finder := crackpoint.NewFinder()
	cf := &ClassFile{
		ThisClass: "com.app.License",
		MethodRefs: []MethodRef{
			{Class: "com.app.License", Name: "verifyLicense", Descriptor: "()Z"},
			{Class: "com.app.User", Name: "isPremium", Descriptor: "()Z"},
		},
		Strings: []string{"hello"},
	}
	points := detectCrackPoints(finder, cf, "com/app/License.class")
	if len(points) == 0 {
		t.Fatal("expected crack points for verifyLicense/isPremium")
	}
	var gotLicense, gotPremium bool
	for _, p := range points {
		if p.Category == "license" {
			gotLicense = true
		}
		if p.Category == "premium" {
			gotPremium = true
		}
		if p.Location.File != "com/app/License.class" {
			t.Errorf("unexpected file %q", p.Location.File)
		}
	}
	if !gotLicense || !gotPremium {
		t.Errorf("missing categories: license=%v premium=%v", gotLicense, gotPremium)
	}
}

func TestClassifyStringSecret(t *testing.T) {
	if _, ok := classifyStringSecret("AKIA1B2C3D4E5F6G7H8J", "com.app.K", "K.class"); !ok {
		t.Error("expected AWS key to classify as secret")
	}
	if _, ok := classifyStringSecret("hello", "com.app.K", "K.class"); ok {
		t.Error("short word must not classify as secret")
	}
	m, ok := classifyStringSecret("ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8", "com.app.K", "K.class")
	if !ok {
		t.Fatal("expected github token to classify as secret")
	}
	if m.Text == "ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8" {
		t.Error("secret value must be masked, not stored verbatim")
	}
}
