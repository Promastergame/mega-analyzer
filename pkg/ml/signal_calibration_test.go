package ml

import "testing"

func TestCalibratedSignalConfidence_Tiers(t *testing.T) {
	tests := []struct {
		name     string
		raw      float64
		evidence []string
		want     float64
	}{
		{"name-only hit cannot be certain", 1.0, []string{"method:startsWith"}, 0.80},
		{"name-only hit keeps lower value", 0.70, []string{"method:isPro"}, 0.70},
		{"single literal capped", 0.90, []string{"crypto_literal:DES"}, 0.85},
		{"single literal keeps lower value", 0.80, []string{"cleartext_url:http://x"}, 0.80},
		{"corroborated evidence keeps value", 0.90, []string{"call:;->getInstance", "crypto_literal:AES/ECB/NoPadding"}, 0.90},
		{"hard ceiling holds", 1.0, []string{"a", "b", "c"}, 0.95},
		{"over-ceiling corroborated clamps", 0.99, []string{"a", "b"}, 0.95},
		{"no evidence is name-only tier", 0.90, nil, 0.80},
		{"negative clamps to zero", -0.5, []string{"a"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CalibratedSignalConfidence(tt.raw, tt.evidence); got != tt.want {
				t.Fatalf("CalibratedSignalConfidence(%v, %q) = %v, want %v",
					tt.raw, tt.evidence, got, tt.want)
			}
		})
	}
}

func TestAnalyzeVulnerabilitySignals_CalibratesNameOnlyGates(t *testing.T) {
	// A bare boolean getter named like a premium gate must not report
	// near-certain confidence from the name alone.
	mi := &MethodInfo{
		Name:           "isPro",
		ReturnsBoolean: true,
		IsShortMethod:  true,
		Calls:          []CallInfo{{FullCall: "Lx;->noop()V"}},
	}
	signals := AnalyzeVulnerabilitySignals(mi)
	if signals == nil {
		t.Fatal("expected signals for isPro gate")
	}
	for _, s := range signals.Signals {
		if s.Kind == VulnPremiumClientGate && s.Confidence > NameOnlyConfidenceCap {
			t.Fatalf("name-only premium gate confidence = %v, want <= %v",
				s.Confidence, NameOnlyConfidenceCap)
		}
		if s.Confidence > MaxStaticSignalConfidence {
			t.Fatalf("signal confidence = %v exceeds ceiling %v",
				s.Confidence, MaxStaticSignalConfidence)
		}
	}
}

func TestAnalyzeVulnerabilitySignals_CeilingHolds(t *testing.T) {
	// Kitchen-sink method: no aggregated signal may exceed the ceiling.
	mi := &MethodInfo{
		Name: "verify",
		Calls: []CallInfo{
			{FullCall: "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"},
			{FullCall: "Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;"},
			{FullCall: "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"},
			{FullCall: "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"},
		},
		StringConsts: []string{"AES/ECB/PKCS5Padding", "http://api.example.com/x", "../etc/passwd"},
	}
	signals := AnalyzeVulnerabilitySignals(mi)
	if signals == nil {
		t.Fatal("expected signals")
	}
	for _, s := range signals.Signals {
		if s.Confidence > MaxStaticSignalConfidence {
			t.Fatalf("kind %q confidence = %v exceeds ceiling %v",
				s.Kind, s.Confidence, MaxStaticSignalConfidence)
		}
	}
}
