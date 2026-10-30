package ml

import "testing"

func TestAgeSignalGetsAgeCategory(t *testing.T) {
	mi := &MethodInfo{
		Name:           "canOpenMatureSection",
		ClassName:      "Lcom/megademo/testapp/AgeGate;",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		Calls:          []CallInfo{{FullCall: "Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z"}},
		StringConsts:   []string{"adult", "age_gate"},
	}
	vs := AnalyzeVulnerabilitySignals(mi)
	if findKind(vs, VulnAgeVerification) == nil {
		t.Fatal("age signal not detected")
	}
	if got := categoryForVulnSignals(vs); got != PatchCatAgeVerification {
		t.Fatalf("category=%q, want %q", got, PatchCatAgeVerification)
	}
}

func TestMethodMetaContextDoesNotLeakAcrossPooledMethods(t *testing.T) {
	first := GetMethodInfo()
	first.Name = "isAdFree"
	first.ClassName = "Lcom/example/Ads;"
	_ = getMethodMetaContext(first)
	PutMethodInfo(first)

	second := GetMethodInfo()
	second.Name = "canOpenMatureSection"
	second.ClassName = "Lcom/example/AgeGate;"
	got := getMethodMetaContext(second)
	PutMethodInfo(second)
	if got == "" || got == "isadfree lcom/example/ads;" {
		t.Fatalf("pooled method context leaked: %q", got)
	}
}
