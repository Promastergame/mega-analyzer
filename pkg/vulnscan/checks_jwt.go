package vulnscan

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// jwtTokenRe extracts JWT-shaped tokens from response bodies. Compiled once
// at package level; checkJWTs runs on every response.
var jwtTokenRe = regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)

// checkJWTs detects and analyzes JWTs in the response headers and body.
// It decodes payloads for sensitive info, checks the "none" algorithm vulnerability,
// and performs an optional dictionary attack if a wordlist is provided.
func (s *Scanner) checkJWTs(resp *http.Response, body string) []Vulnerability {
	var list []Vulnerability
	var jwts []string
	seen := make(map[string]bool)

	// Extract from Authorization header
	auth := resp.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[7:])
		if isJWT(token) && !seen[token] {
			jwts = append(jwts, token)
			seen[token] = true
		}
	}

	// Extract from Set-Cookie headers
	for _, cookie := range resp.Cookies() {
		if isJWT(cookie.Value) && !seen[cookie.Value] {
			jwts = append(jwts, cookie.Value)
			seen[cookie.Value] = true
		}
	}

	// Extract from body using regex
	matches := jwtTokenRe.FindAllString(body, -1)
	for _, match := range matches {
		if !seen[match] {
			jwts = append(jwts, match)
			seen[match] = true
		}
	}

	for _, token := range jwts {
		// Basic analysis
		list = append(list, s.analyzeJWTPayload(token)...)

		// Active checks (only if we own the target)
		if s.Config.IOwnThisTarget {
			list = append(list, s.checkJWTNoneAlg(token)...)
			list = append(list, s.checkJWTWeakSecret(token)...)
		}
	}

	return list
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && strings.HasPrefix(token, "eyJ")
}

func (s *Scanner) analyzeJWTPayload(token string) []Vulnerability {
	var list []Vulnerability
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return list
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return list
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return list
	}

	// Check for sensitive fields in payload
	sensitiveKeys := []string{"email", "password", "role", "admin", "privilege", "is_admin"}
	var foundSensitive []string
	for _, key := range sensitiveKeys {
		if _, exists := payload[key]; exists {
			foundSensitive = append(foundSensitive, key)
		}
	}

	if len(foundSensitive) > 0 {
		list = append(list, Vulnerability{
			ID:          "WS-JWT-001",
			Name:        "JWT Sensitive Data Exposure",
			Description: fmt.Sprintf("The JWT payload contains potentially sensitive fields: %s. JWT payloads are base64-encoded, not encrypted, and can be easily read.", strings.Join(foundSensitive, ", ")),
			Severity:    SeverityLow,
			URL:         s.Target,
			Evidence:    string(payloadRaw),
			Mitigation:  "Do not store sensitive information (like PII or passwords) in the JWT payload. Use opaque tokens if confidentiality is required.",
		})
	}

	// Header-controlled key selection is security-sensitive even before an
	// active forgery attempt. Decode and validate the protected header as data.
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err == nil {
		var header map[string]interface{}
		if json.Unmarshal(headerRaw, &header) == nil {
			if jwk, exists := header["jwk"]; exists && jwk != nil {
				list = append(list, Vulnerability{
					ID: "WS-JWT-004", Name: "JWT Embedded JWK Header Accepted",
					Description: "The token carries an attacker-controlled jwk key in its protected header. If the verifier trusts embedded keys instead of a server-side allowlist, an attacker can self-sign arbitrary tokens.",
					Severity:    SeverityHigh, URL: s.Target, Evidence: truncate(string(headerRaw), 300),
					Mitigation: "Ignore token-supplied jwk values unless they are cryptographically bound to a trusted issuer. Resolve keys only from a pinned issuer/JWKS configuration and enforce the expected algorithm.",
				})
			}
			for _, key := range []string{"jku", "x5u"} {
				if raw, ok := header[key].(string); ok && raw != "" {
					u, parseErr := url.Parse(raw)
					if parseErr == nil && u.IsAbs() && u.Hostname() != "" {
						list = append(list, Vulnerability{
							ID: "WS-JWT-006", Name: "JWT External Key URL Header",
							Description: fmt.Sprintf("The JWT controls the %s key URL. A verifier that fetches this URL without an exact issuer-bound allowlist is exposed to attacker-key substitution and SSRF.", key),
							Severity:    SeverityHigh, URL: s.Target, Parameter: key, Evidence: truncate(raw, 240),
							Mitigation: "Reject token-controlled key URLs. Pin JWKS/cert locations in server configuration, require HTTPS, block private/link-local destinations, and cache verified keys by trusted issuer and key ID.",
						})
					}
				}
			}
			if kid, ok := header["kid"].(string); ok && suspiciousKID(kid) {
				list = append(list, Vulnerability{
					ID: "WS-JWT-005", Name: "JWT kid Path/Injection Metacharacters",
					Description: "The JWT key identifier contains traversal or injection metacharacters. Vulnerable verifiers concatenate kid into filesystem, SQL, shell, or cache-key lookups, enabling key substitution or injection.",
					Severity:    SeverityMedium, URL: s.Target, Parameter: "kid", Evidence: truncate(kid, 200),
					Mitigation: "Treat kid as an opaque allowlisted identifier. Enforce a strict length/character policy and map it to preconfigured keys; never concatenate it into paths, SQL, commands, or URLs.",
				})
			}
		}
	}

	return list
}

func suspiciousKID(kid string) bool {
	if len(kid) > 128 || strings.Contains(kid, "..") {
		return true
	}
	return strings.ContainsAny(kid, `/\\'";|`+"`"+`\r\n\t `)
}

func (s *Scanner) checkJWTNoneAlg(token string) []Vulnerability {
	var list []Vulnerability
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return list
	}

	// Modify header to alg: none
	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return list
	}
	header["alg"] = "none"
	newHeaderJSON, _ := json.Marshal(header)
	newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

	// Modify payload to elevate privileges (e.g. admin: true)
	payloadRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return list
	}
	payload["admin"] = true
	newPayloadJSON, _ := json.Marshal(payload)
	newPayloadB64 := base64.RawURLEncoding.EncodeToString(newPayloadJSON)

	noneAlgToken := fmt.Sprintf("%s.%s.", newHeaderB64, newPayloadB64)

	// Baseline: same header/payload but with the signature corrupted, to confirm
	// the endpoint actually rejects an invalid token before trusting a 200 on the
	// none-alg probe. Without this, an endpoint that never gates on the token
	// (public page, or the header isn't checked for this route) would falsely
	// look vulnerable.
	baselineToken := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	baselineStatus, err := s.sendJWTAuthProbe(baselineToken)
	if err != nil || baselineStatus == 200 {
		return list
	}

	status, err := s.sendJWTAuthProbe(noneAlgToken)
	if err != nil {
		return list
	}

	if status == 200 {
		list = append(list, Vulnerability{
			ID:          "WS-JWT-002",
			Name:        "JWT 'none' Algorithm Accepted",
			Description: "The server appears to accept JWTs with the 'none' algorithm, allowing attackers to forge tokens without a valid signature.",
			Severity:    SeverityCritical,
			URL:         s.Target,
			Payload:     noneAlgToken,
			Evidence:    fmt.Sprintf("Server returned %d for alg:none token after rejecting (HTTP %d) the same claims with a corrupted signature", status, baselineStatus),
			Mitigation:  "Configure the JWT library to require specific algorithms (e.g., HS256, RS256) and reject 'none'.",
		})
	}

	return list
}

// sendJWTAuthProbe sends a GET to the target with the given token as a Bearer
// credential and returns the response status code.
func (s *Scanner) sendJWTAuthProbe(token string) (int, error) {
	req, err := http.NewRequest("GET", s.Target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1*1024*1024)) //nolint:errcheck
	resp.Body.Close()
	return resp.StatusCode, nil
}

func (s *Scanner) checkJWTWeakSecret(token string) []Vulnerability {
	var list []Vulnerability

	if s.Config.JWTWordlist == "" {
		return list
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return list
	}

	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	json.Unmarshal(headerRaw, &header)
	alg, ok := header["alg"].(string)
	if !ok || !strings.HasPrefix(alg, "HS") {
		return list // Only HMAC supports offline cracking
	}

	message := fmt.Sprintf("%s.%s", parts[0], parts[1])
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return list
	}

	file, err := os.Open(s.Config.JWTWordlist)
	if err != nil {
		s.log("[-] Failed to open JWT wordlist: %v\n", err)
		return list
	}
	defer file.Close()

	s.log("[*] Brute-forcing JWT secret using wordlist: %s\n", s.Config.JWTWordlist)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		secret := scanner.Text()

		var mac []byte
		if alg == "HS256" {
			h := hmac.New(sha256.New, []byte(secret))
			h.Write([]byte(message))
			mac = h.Sum(nil)
		} else if alg == "HS384" {
			h := hmac.New(sha512.New384, []byte(secret))
			h.Write([]byte(message))
			mac = h.Sum(nil)
		} else if alg == "HS512" {
			h := hmac.New(sha512.New, []byte(secret))
			h.Write([]byte(message))
			mac = h.Sum(nil)
		}

		if hmac.Equal(mac, signatureBytes) {
			list = append(list, Vulnerability{
				ID:          "WS-JWT-003",
				Name:        "JWT Weak Secret Key",
				Description: "The JWT is signed with a weak secret key that was cracked via offline dictionary attack.",
				Severity:    SeverityCritical,
				URL:         s.Target,
				Evidence:    fmt.Sprintf("Cracked secret: %s", secret),
				Mitigation:  "Use a strong, randomly generated, long secret key for HMAC signing (at least 256 bits).",
			})
			break // Stop once found
		}
	}

	return list
}
