package secrets

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// makeJWT builds a structurally valid (unsigned-content) JWT from a header and
// claims so tests never embed a real credential.
func makeJWT(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + ".c2lnbmF0dXJl"
}

func TestDecodeJWT_Valid(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"iss": "acme", "sub": "user-1", "exp": float64(time.Now().Add(time.Hour).Unix())},
	)
	info, ok := DecodeJWT(tok)
	if !ok {
		t.Fatal("expected valid JWT to decode")
	}
	if info.Algorithm != "HS256" {
		t.Errorf("alg = %q, want HS256", info.Algorithm)
	}
	if info.Issuer != "acme" || info.Subject != "user-1" {
		t.Errorf("claims mismatch: iss=%q sub=%q", info.Issuer, info.Subject)
	}
	if info.Expired {
		t.Error("future-exp JWT must not be marked expired")
	}
}

func TestDecodeJWT_Expired(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "RS256", "typ": "JWT"},
		map[string]any{"exp": float64(time.Now().Add(-time.Hour).Unix())},
	)
	info, ok := DecodeJWT(tok)
	if !ok {
		t.Fatal("expected decode ok")
	}
	if !info.Expired {
		t.Error("past-exp JWT must be marked expired")
	}
}

func TestDecodeJWT_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not.a.jwt",
		"onlyonepart",
		"a.b", // only two segments
		base64.RawURLEncoding.EncodeToString([]byte(`{"no":"alg"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".sig", // header lacks alg
	}
	for _, c := range cases {
		if _, ok := DecodeJWT(c); ok {
			t.Errorf("expected %q to be rejected as JWT", c)
		}
	}
}

func TestVerifyStructure_JWTExpiredDemotesInDetect(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"exp": float64(time.Now().Add(-48 * time.Hour).Unix())},
	)
	f := findRule(DetectProviders("Authorization: Bearer "+tok, "prod"), "secret/jwt-token")
	if f == nil {
		t.Fatal("expected jwt finding")
	}
	if f.Severity != "low" {
		t.Errorf("expired JWT should be demoted to low, got %q", f.Severity)
	}
	if f.Verified {
		t.Error("expired token should not be reported as verified")
	}
}

func TestVerifyStructure_JWTValidBoosts(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"iss": "acme", "exp": float64(time.Now().Add(72 * time.Hour).Unix())},
	)
	f := findRule(DetectProviders("token="+tok, "prod"), "secret/jwt-token")
	if f == nil {
		t.Fatal("expected jwt finding")
	}
	if !f.Verified {
		t.Error("valid JWT should be marked verified")
	}
	if f.Validation == "" {
		t.Error("valid JWT should carry a validation note")
	}
}

func TestVerifyStructure_PrivateKey(t *testing.T) {
	v := VerifyStructure("secret/private-key", "-----BEGIN RSA PRIVATE KEY-----")
	if !v.Verified {
		t.Error("PEM marker should verify")
	}
}

func TestLooksBase64AndHex(t *testing.T) {
	if !looksBase64("QWxhZGRpbjpvcGVuIHNlc2FtZQ==") {
		t.Error("expected base64 recognition")
	}
	if looksBase64("has space in it here") {
		t.Error("string with spaces is not base64")
	}
	if !looksHex("deadbeefdeadbeefdeadbeef") {
		t.Error("expected hex recognition")
	}
	if looksHex("deadbeefz") {
		t.Error("odd/invalid hex should be rejected")
	}
}

func TestTimeNowInjectable(t *testing.T) {
	// Pin now to the far future so a normally-valid token reads as expired.
	orig := timeNow
	defer func() { timeNow = orig }()
	timeNow = func() time.Time { return time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC) }

	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"exp": float64(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix())},
	)
	info, ok := DecodeJWT(tok)
	if !ok || !info.Expired {
		t.Errorf("with pinned far-future now, 2100 token should be expired (ok=%v expired=%v)", ok, info.Expired)
	}
}
