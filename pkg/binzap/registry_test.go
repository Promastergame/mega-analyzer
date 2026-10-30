package binzap

import "testing"

func TestDefaultRegistryPacks(t *testing.T) {
	reg := DefaultRegistry()
	if len(reg.EnabledRules()) == 0 {
		t.Fatal("expected enabled rules")
	}
	packs := reg.Packs()
	has := map[string]bool{}
	for _, p := range packs {
		has[p] = true
	}
	for _, want := range []string{"core", "mobile", "malware"} {
		if !has[want] {
			t.Errorf("expected pack %q present, packs=%v", want, packs)
		}
	}
}

func TestProfileFiltersByPack(t *testing.T) {
	reg := DefaultRegistry()
	reg.ApplyProfile(Profile{Name: "core-only", Packs: []string{"core"}})
	for _, e := range reg.All() {
		if e.Meta.Pack != "core" && e.Enabled {
			t.Errorf("rule %s in pack %s should be disabled", e.Meta.ID, e.Meta.Pack)
		}
	}
}

func TestDuplicateRegistrationRejected(t *testing.T) {
	reg := NewRegistry()
	rule := &RuleWeakCrypto{}
	if err := reg.Register(rule, RuleMetadata{ID: rule.ID()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := reg.Register(rule, RuleMetadata{ID: rule.ID()}); err == nil {
		t.Error("expected duplicate registration to fail")
	}
}

func TestApplyOverride(t *testing.T) {
	reg := DefaultRegistry()
	sev := SeverityLow
	enabled := false
	if err := reg.ApplyOverride("BZ-PASS-001", Override{Severity: &sev, Enabled: &enabled}); err != nil {
		t.Fatalf("override failed: %v", err)
	}
	e, ok := reg.Get("BZ-PASS-001")
	if !ok || e.Meta.Severity != SeverityLow || e.Enabled {
		t.Errorf("override not applied: %+v", e)
	}

	if err := reg.ApplyOverride("missing-rule", Override{}); err == nil {
		t.Error("expected error for missing rule override")
	}

	meta := reg.MetadataByID()
	if len(meta) == 0 || meta["BZ-PASS-001"].ID != "BZ-PASS-001" {
		t.Errorf("unexpected MetadataByID: %+v", meta)
	}
}

func TestMustRegisterPanic(t *testing.T) {
	reg := NewRegistry()
	rule := &RuleWeakCrypto{}
	reg.MustRegister(rule, RuleMetadata{ID: rule.ID()})
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate MustRegister")
		}
	}()
	reg.MustRegister(rule, RuleMetadata{ID: rule.ID()})
}
