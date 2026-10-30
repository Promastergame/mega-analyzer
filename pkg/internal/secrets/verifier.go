package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// timeNow is indirected so tests can pin "now" when checking JWT expiry.
var timeNow = time.Now

// Verification is the result of an offline, network-free structural check of a
// credential candidate. It never contacts a provider: it only inspects the
// token's own encoded structure (base64 segments, JSON claims, charset), which
// is enough to prove a match is well-formed or to prove it is already dead
// (e.g. an expired JWT). Callers use Verified to raise confidence and Expired /
// Placeholder to demote a finding without ever dropping it.
type Verification struct {
	Verified    bool   // structure is provably well-formed for this credential type
	Expired     bool   // token carries an embedded expiry that is already in the past
	Placeholder bool   // structure proves this is a documentation/example value
	Detail      string // short human-readable explanation for the report
}

// JWTInfo holds the decoded, unverified claims of a JSON Web Token. The
// signature is never checked (that needs the signing key); we only parse the
// header and payload, which is enough to surface algorithm, issuer and expiry.
type JWTInfo struct {
	Algorithm string
	Type      string
	Issuer    string
	Subject   string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	NotBefore time.Time
	Expired   bool
	Claims    map[string]any
}

// b64urlDecode decodes a base64url segment tolerating missing padding, which
// JWT segments always omit.
func b64urlDecode(seg string) ([]byte, bool) {
	if seg == "" {
		return nil, false
	}
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	// Some encoders emit standard base64 alphabet or include padding.
	if b, err := base64.URLEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	if b, err := base64.StdEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	return nil, false
}

// DecodeJWT parses the header and payload of a JWT without verifying its
// signature. It returns ok=false if the value is not a structurally valid JWT.
func DecodeJWT(token string) (JWTInfo, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return JWTInfo{}, false
	}
	headerBytes, ok := b64urlDecode(parts[0])
	if !ok {
		return JWTInfo{}, false
	}
	payloadBytes, ok := b64urlDecode(parts[1])
	if !ok {
		return JWTInfo{}, false
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return JWTInfo{}, false
	}
	// A JWT header must at minimum declare an algorithm.
	alg, _ := header["alg"].(string)
	if alg == "" {
		return JWTInfo{}, false
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return JWTInfo{}, false
	}

	info := JWTInfo{
		Algorithm: alg,
		Claims:    claims,
	}
	if typ, ok := header["typ"].(string); ok {
		info.Type = typ
	}
	if iss, ok := claims["iss"].(string); ok {
		info.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		info.Subject = sub
	}
	switch aud := claims["aud"].(type) {
	case string:
		info.Audience = aud
	case []any:
		var parts []string
		for _, a := range aud {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		info.Audience = strings.Join(parts, ",")
	}
	info.IssuedAt = claimTime(claims["iat"])
	info.ExpiresAt = claimTime(claims["exp"])
	info.NotBefore = claimTime(claims["nbf"])
	if !info.ExpiresAt.IsZero() && info.ExpiresAt.Before(timeNow()) {
		info.Expired = true
	}
	return info, true
}

// claimTime converts a numeric JWT timestamp claim (seconds since epoch) into a
// time.Time. JSON numbers decode as float64.
func claimTime(v any) time.Time {
	switch n := v.(type) {
	case float64:
		if n <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(n), 0).UTC()
	case json.Number:
		if i, err := n.Int64(); err == nil && i > 0 {
			return time.Unix(i, 0).UTC()
		}
	}
	return time.Time{}
}

// looksBase64 reports whether s is plausibly a base64/base64url-encoded blob of
// meaningful length — a positive signal that a token carries real encoded
// entropy rather than a hand-typed label.
func looksBase64(s string) bool {
	if len(s) < 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_' || c == '=':
		default:
			return false
		}
	}
	return true
}

// looksHex reports whether s is a pure hex string of even length — the shape of
// many API keys and digests.
func looksHex(s string) bool {
	if len(s) < 16 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// VerifyStructure runs the offline structural check appropriate to a rule and
// returns what it could prove about the candidate. It is intentionally
// conservative: a false Verified never means "not a secret", only "structure
// could not be independently confirmed".
func VerifyStructure(ruleID, value string) Verification {
	value = strings.TrimSpace(value)

	switch {
	case ruleID == "secret/jwt-token" || strings.HasPrefix(value, "eyJ"):
		if info, ok := DecodeJWT(value); ok {
			detail := "well-formed JWT (alg=" + info.Algorithm + ")"
			if info.Issuer != "" {
				detail += ", iss=" + info.Issuer
			}
			if !info.ExpiresAt.IsZero() {
				detail += ", exp=" + info.ExpiresAt.Format("2006-01-02")
			}
			return Verification{
				Verified: true,
				Expired:  info.Expired,
				Detail:   detail,
			}
		}
		return Verification{}

	case ruleID == "secret/private-key":
		// A PEM marker is self-verifying by definition.
		return Verification{Verified: true, Detail: "PEM private key block"}

	case ruleID == "secret/github-token" || ruleID == "secret/npm-token":
		// GitHub classic and npm tokens embed a CRC32 checksum. Validating it
		// is pure math, fully offline. A failed checksum proves the token is
		// fabricated, so the finding is demoted exactly like a dead one.
		if cs := ValidateTokenChecksum(value); cs.Applicable {
			if cs.Valid {
				return Verification{Verified: true, Detail: cs.Detail}
			}
			return Verification{Expired: true, Detail: cs.Detail}
		}
		return Verification{}

	case ruleID == "secret/aws-access-key":
		// The AWS account id is recoverable from a key id by a base32 decode
		// and a bit shift - a strong, offline proof of well-formedness.
		if acct, ok := AWSAccountIDFromAccessKey(value); ok {
			return Verification{Verified: true, Detail: "well-formed AWS key id, embedded account id " + acct}
		}
		return Verification{}
	}

	// For opaque provider tokens, prove the variable portion is genuinely an
	// encoded blob (base64/hex) rather than a low-variety label. This is a
	// structural signal, not proof of liveness.
	tok := entropyBearingPart(ruleID, value)
	if looksBase64(tok) || looksHex(tok) {
		if CalculateEntropy(tok) >= 3.2 && !isRepeatingString(tok) {
			return Verification{Verified: true, Detail: "high-entropy encoded token body"}
		}
	}
	return Verification{}
}
