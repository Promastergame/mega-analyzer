// Package main: jwt.go implements a small, self-contained, intentionally
// insecure JWT-like token codec.
//
// ============================================================================
// WARNING: THIS FILE IS DELIBERATELY VULNERABLE. DO NOT COPY THIS PATTERN.
// ============================================================================
//
// It is written from scratch (no external JWT library) so the bug is fully
// visible in this repo's own source rather than hidden inside a dependency.
// The bug is CWE-347 (Improper Verification of Cryptographic Signature):
// the verifier trusts the client-supplied `alg` field in the token header.
// A token with `"alg":"none"` is accepted with NO signature check at all,
// so anyone who can craft three base64url segments can mint an admin
// session with zero credentials.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// jwtSecret is a hardcoded, publicly-documented placeholder secret used to
// sign/verify HS256 tokens in this lab. It is intentionally weak and
// intentionally checked into source control — never do this in real code.
const jwtSecret = "lab-insecure-secret-change-me"

// Claims mirrors the handful of fields this lab's tokens carry. Real JWTs
// would use registered claim names (sub, exp, ...); kept simple here.
type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

// header is the token header this lab understands. `Alg` is the field an
// attacker controls and that the vulnerable verifier trusts blindly.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// b64urlEncode / b64urlDecode implement unpadded base64url, matching the
// segment encoding real JWTs use.
func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// signHS256 builds a properly-signed three-segment token:
// base64url(header).base64url(payload).base64url(hmac_sha256(header.payload, jwtSecret))
func signHS256(claims Claims) string {
	h := header{Alg: "HS256", Typ: "JWT"}
	headerJSON, _ := json.Marshal(h)
	payloadJSON, _ := json.Marshal(claims)

	headerSeg := b64urlEncode(headerJSON)
	payloadSeg := b64urlEncode(payloadJSON)

	signingInput := headerSeg + "." + payloadSeg
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigSeg := b64urlEncode(sig)

	return signingInput + "." + sigSeg
}

// tokenAlgNone reports whether the raw token's decoded header claims
// alg == "none", without validating anything else about it. Used only for
// the loud backdoor-usage log line in main.go.
func tokenAlgNone(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	headerJSON, err := b64urlDecode(parts[0])
	if err != nil {
		return false
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return false
	}
	return strings.EqualFold(h.Alg, "none")
}

// parseAndVerify decodes a token and, depending on the algorithm the token
// itself claims to use, either verifies an HS256 signature or (the bug)
// skips verification entirely for "none".
func parseAndVerify(token string) (Claims, error) {
	var claims Claims

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("malformed token: expected 3 segments")
	}
	headerSeg, payloadSeg, sigSeg := parts[0], parts[1], parts[2]

	headerJSON, err := b64urlDecode(headerSeg)
	if err != nil {
		return claims, errors.New("malformed token: bad header encoding")
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return claims, errors.New("malformed token: bad header json")
	}

	payloadJSON, err := b64urlDecode(payloadSeg)
	if err != nil {
		return claims, errors.New("malformed token: bad payload encoding")
	}

	switch strings.ToLower(h.Alg) {
	case "none":
		// INTENTIONALLY INSECURE: trusts client-controlled alg
		//
		// The token's own header told us not to bother checking a
		// signature, and we just... didn't. The sigSeg is not even
		// inspected below (an attacker typically leaves it empty).
		// A correct implementation must pin the expected algorithm
		// server-side (e.g. always require HS256) instead of reading
		// it from attacker-controlled input.
		_ = sigSeg
		if err := json.Unmarshal(payloadJSON, &claims); err != nil {
			return claims, errors.New("malformed token: bad payload json")
		}
		return claims, nil

	case "hs256":
		sig, err := b64urlDecode(sigSeg)
		if err != nil {
			return claims, errors.New("malformed token: bad signature encoding")
		}
		signingInput := headerSeg + "." + payloadSeg
		mac := hmac.New(sha256.New, []byte(jwtSecret))
		mac.Write([]byte(signingInput))
		expected := mac.Sum(nil)
		if subtle.ConstantTimeCompare(sig, expected) != 1 {
			return claims, errors.New("invalid signature")
		}
		if err := json.Unmarshal(payloadJSON, &claims); err != nil {
			return claims, errors.New("malformed token: bad payload json")
		}
		return claims, nil

	default:
		return claims, errors.New("unsupported alg")
	}
}
