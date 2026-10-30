package secrets

import "testing"

func TestCalculateEntropy(t *testing.T) {
	// Standard english word should have relatively low entropy
	word := "password"
	wordEntropy := CalculateEntropy(word)

	// Random Base64 high-quality key should have high entropy
	secret := "AKIAIOSFODNN7EXAMPLE"
	secretEntropy := CalculateEntropy(secret)

	if wordEntropy >= secretEntropy {
		t.Errorf("expected secret entropy (%f) to be greater than word entropy (%f)", secretEntropy, wordEntropy)
	}

	// Empty string entropy should be 0.0
	if h := CalculateEntropy(""); h != 0.0 {
		t.Errorf("empty string entropy = %f, want 0.0", h)
	}
}

func TestTriage_ShortAndPlaceholder(t *testing.T) {
	// Too short
	res := Triage("secret/generic", "abc", "apiKey = 'abc'")
	if res.Verdict != "placeholder" || res.Severity != "info" {
		t.Errorf("short key: got verdict %s, severity %s", res.Verdict, res.Severity)
	}

	// Repeating sequence
	res2 := Triage("secret/generic", "0000000000000", "apiKey = '0000000000000'")
	if res2.Verdict != "placeholder" || res2.Severity != "info" {
		t.Errorf("repeating key: got verdict %s, severity %s", res2.Verdict, res2.Severity)
	}
}

func TestTriage_TestMockContext(t *testing.T) {
	// High-entropy key, but in a test variable context
	val := "q3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C"
	res := Triage("secret/generic", val, "testKey = '"+val+"'")
	if res.Verdict != "placeholder" || res.Severity != "medium" {
		t.Errorf("test key context: got verdict %s, severity %s, detail: %s", res.Verdict, res.Severity, res.Detail)
	}
}

func TestTriage_ExpiredContext(t *testing.T) {
	val := "q3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C"
	res := Triage("secret/generic", val, "old_key = '"+val+"' // revoked key")
	if res.Verdict != "expired-looking" || res.Severity != "low" {
		t.Errorf("expired context: got verdict %s, severity %s", res.Verdict, res.Severity)
	}
}

func TestTriage_RealLooking(t *testing.T) {
	// High-entropy token, standard context
	val := "q3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C"
	res := Triage("secret/generic", val, "productionToken = '"+val+"'")
	if res.Verdict != "real-looking" || res.Severity != "high" {
		t.Errorf("real key: got verdict %s, severity %s, detail: %s", res.Verdict, res.Severity, res.Detail)
	}
}
