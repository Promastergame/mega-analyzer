package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// TestSignAndVerifyRoundTrip proves the "correct" path works: a token
// legitimately signed with the server secret round-trips through
// parseAndVerify with its claims intact.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	want := Claims{Sub: "alice", Role: "user", Exp: 9999999999}
	token := signHS256(want)

	got, err := parseAndVerify(token)
	if err != nil {
		t.Fatalf("parseAndVerify returned error for legit token: %v", err)
	}
	if got != want {
		t.Fatalf("claims mismatch: got %+v, want %+v", got, want)
	}
}

// TestAlgNoneBypassIsAccepted documents and demonstrates the intentional
// vulnerability (CWE-347): a hand-crafted token with header {"alg":"none"}
// and an empty signature segment is accepted by parseAndVerify, and the
// attacker-controlled role="admin" claim is trusted as-is. This test is NOT
// meant to be "fixed" — it exists to prove the bug is present and stays
// present, mirroring how the real exploit works over HTTP.
func TestAlgNoneBypassIsAccepted(t *testing.T) {
	headerSeg := b64urlEncode(mustJSON(t, map[string]string{"alg": "none", "typ": "JWT"}))
	payloadSeg := b64urlEncode(mustJSON(t, Claims{Sub: "attacker", Role: "admin", Exp: 9999999999}))
	forged := headerSeg + "." + payloadSeg + "." // empty signature segment

	claims, err := parseAndVerify(forged)
	if err != nil {
		t.Fatalf("expected forged alg=none token to be accepted, got error: %v", err)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected forged token to carry role=admin, got role=%q", claims.Role)
	}
	if claims.Sub != "attacker" {
		t.Fatalf("expected forged token sub=attacker, got %q", claims.Sub)
	}

	if !tokenAlgNone(forged) {
		t.Fatalf("tokenAlgNone should detect the forged alg=none token")
	}
}

// TestWrongSecretRejected confirms the HS256 branch still does real
// signature verification: a token signed with a different secret than
// jwtSecret must be rejected.
func TestWrongSecretRejected(t *testing.T) {
	claims := Claims{Sub: "bob", Role: "user", Exp: 9999999999}
	headerSeg := b64urlEncode(mustJSON(t, map[string]string{"alg": "HS256", "typ": "JWT"}))
	payloadSeg := b64urlEncode(mustJSON(t, claims))
	signingInput := headerSeg + "." + payloadSeg

	mac := hmac.New(sha256.New, []byte("totally-wrong-secret"))
	mac.Write([]byte(signingInput))
	sigSeg := b64urlEncode(mac.Sum(nil))

	forged := signingInput + "." + sigSeg

	if _, err := parseAndVerify(forged); err == nil {
		t.Fatalf("expected token signed with wrong secret to be rejected")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
