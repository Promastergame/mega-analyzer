package vulnscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// API-BOLA-001 and API-DESER-001 deliberately require differential evidence.
// A single 200 or generic 500 is never enough to report either issue.

var objectIDParam = regexp.MustCompile(`(?i)^(id|user_?id|account_?id|profile_?id|order_?id|invoice_?id|document_?id|resource_?id)$`)

// checkAPIBOLA mutates an object identifier already present in the target URL.
// It reports only when (1) the original authenticated object exists, (2) a
// neighbouring object also returns identity-bearing data under the same
// principal, and (3) the same mutated request is denied without credentials.
// That three-way comparison separates BOLA from public resources and 200 error
// pages. A scanner cannot prove cross-tenant ownership with one account, so the
// finding is explicitly classified as high-confidence "potential BOLA".
func (s *Scanner) checkAPIBOLA() []Vulnerability {
	if s.BaseURL == nil || (s.Config.AuthBearer == "" && s.Config.AuthCookie == "") {
		return nil
	}
	q := s.BaseURL.Query()
	for name, values := range q {
		if !objectIDParam.MatchString(name) || len(values) == 0 {
			continue
		}
		original, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil || original < 0 {
			continue
		}
		baseStatus, baseBody, ok := s.apiObjectRequest(s.BaseURL, true)
		if !ok || baseStatus < 200 || baseStatus >= 300 {
			continue
		}
		baseIdentity := extractIdentityEvidence(baseBody)
		if len(baseIdentity) == 0 {
			continue
		}

		for _, candidate := range []int64{original + 1, original - 1} {
			if candidate < 0 || candidate == original {
				continue
			}
			mutated := *s.BaseURL
			mq := cloneValues(q)
			mq.Set(name, strconv.FormatInt(candidate, 10))
			mutated.RawQuery = mq.Encode()
			mutStatus, mutBody, mok := s.apiObjectRequest(&mutated, true)
			if !mok || mutStatus < 200 || mutStatus >= 300 {
				continue
			}
			mutIdentity := extractIdentityEvidence(mutBody)
			if len(mutIdentity) == 0 || identityMapsEqual(baseIdentity, mutIdentity) {
				continue
			}
			anonStatus, anonBody, aok := s.apiObjectRequest(&mutated, false)
			if !aok || !isAuthorizationDenied(anonStatus, anonBody) {
				continue
			}
			return []Vulnerability{{
				ID:          "API-BOLA-001",
				Name:        "Potential Broken Object Level Authorization (BOLA)",
				Description: fmt.Sprintf("An authenticated request for %s=%d returned a different identity-bearing object, while the same request without credentials was denied. This strongly suggests authentication exists but per-object authorization may be missing.", name, candidate),
				Severity:    SeverityHigh,
				URL:         mutated.String(),
				Parameter:   name,
				Payload:     strconv.FormatInt(candidate, 10),
				Evidence:    fmt.Sprintf("original identity=%v; mutated identity=%v; authenticated HTTP %d; anonymous HTTP %d", baseIdentity, mutIdentity, mutStatus, anonStatus),
				Mitigation:  "Enforce object-level authorization on every API read/write using the authenticated subject and tenant, not only possession of an object ID. Add negative tests between two distinct user accounts.",
			}}
		}
	}
	return nil
}

func (s *Scanner) apiObjectRequest(u *url.URL, authenticated bool) (int, []byte, bool) {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, false
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	if authenticated {
		s.applyAuthHeaders(req)
	} else {
		// Opt out of gateway credential injection: this probe must reach the
		// target genuinely unauthenticated for the differential to be valid.
		req = WithAnonymousRequest(req)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, nil, false
	}
	defer resp.Body.Close()
	body, err := ReadBodyBounded(resp, int64(maxOrDefault(s.Config.MaxBodyBytes, 5<<20)))
	return resp.StatusCode, body, err == nil
}

func extractIdentityEvidence(body []byte) map[string]string {
	var v interface{}
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	out := make(map[string]string)
	identityKeys := map[string]bool{"id": true, "userid": true, "user_id": true, "accountid": true, "account_id": true, "ownerid": true, "owner_id": true, "tenantid": true, "tenant_id": true, "email": true, "username": true}
	var walk func(interface{}, int)
	walk = func(x interface{}, depth int) {
		if depth > 5 || len(out) >= 12 {
			return
		}
		switch vv := x.(type) {
		case map[string]interface{}:
			for k, val := range vv {
				lk := strings.ToLower(k)
				if identityKeys[lk] {
					switch scalar := val.(type) {
					case string:
						out[lk] = truncate(scalar, 80)
					case float64, bool:
						out[lk] = fmt.Sprint(scalar)
					}
				}
				walk(val, depth+1)
			}
		case []interface{}:
			for i, val := range vv {
				if i >= 3 {
					break
				}
				walk(val, depth+1)
			}
		}
	}
	walk(v, 0)
	return out
}

func identityMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func isAuthorizationDenied(status int, body []byte) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	if status < 400 {
		return false
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "unauthor") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "access denied")
}

type deserProbe struct {
	contentType string
	payload     []byte
	family      string
	signatures  []string
}

var apiDeserProbes = []deserProbe{
	{contentType: "application/x-java-serialized-object", payload: []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00}, family: "Java ObjectInputStream", signatures: []string{"streamcorruptedexception", "invalid stream header", "objectinputstream", "java.io.optionaldataexception"}},
	{contentType: "application/json", payload: []byte(`{"@type":"mega.analyzer.NonExistentProbe","value":"probe"}`), family: "JSON polymorphic type", signatures: []string{"invalidtypeidexception", "could not resolve type id", "auto type is not support", "typenamehandling", "classnotfoundexception"}},
	{contentType: "application/x-yaml", payload: []byte("!!java/object:mega.analyzer.NonExistentProbe {}\n"), family: "YAML object constructor", signatures: []string{"could not determine a constructor", "cannot create property", "class not found", "constructorexception"}},
}

// checkAPIDeserialization uses inert, deliberately non-instantiable type names.
// It reports only a framework-specific deserializer exception newly introduced
// by the probe; generic 4xx/5xx responses do not count.
func (s *Scanner) checkAPIDeserialization() []Vulnerability {
	if s.BaseURL == nil {
		return nil
	}
	baseStatus, baseBody, ok := s.sendDeserProbe("application/json", []byte(`{"mega_probe":"baseline"}`))
	if !ok {
		return nil
	}
	baseLower := strings.ToLower(string(baseBody))
	for _, p := range apiDeserProbes {
		status, body, pok := s.sendDeserProbe(p.contentType, p.payload)
		if !pok {
			continue
		}
		lower := strings.ToLower(string(body))
		for _, sig := range p.signatures {
			if strings.Contains(lower, sig) && !strings.Contains(baseLower, sig) {
				return []Vulnerability{{
					ID:          "API-DESER-001",
					Name:        "Unsafe Deserialization Attack Surface",
					Description: fmt.Sprintf("The API passed attacker-controlled input to a %s deserializer and disclosed a framework-specific type/stream exception. This confirms a native object-deserialization path, which may enable gadget-chain code execution or data tampering when unsafe types are permitted.", p.family),
					Severity:    SeverityHigh,
					URL:         s.Target,
					Parameter:   "request body",
					Payload:     fmt.Sprintf("Content-Type: %s (%d-byte inert probe)", p.contentType, len(p.payload)),
					Evidence:    fmt.Sprintf("baseline HTTP %d; probe HTTP %d; unique signature %q; response=%s", baseStatus, status, sig, truncate(string(body), 300)),
					Mitigation:  "Do not deserialize native objects from untrusted input. Use a schema-bound DTO format, disable polymorphic/default typing and YAML object constructors, allowlist concrete types, and keep gadget-bearing libraries out of the runtime classpath.",
				}}
			}
		}
	}
	return nil
}

func (s *Scanner) sendDeserProbe(contentType string, payload []byte) (int, []byte, bool) {
	req, err := http.NewRequest(http.MethodPost, s.Target, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, false
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain;q=0.8")
	s.applyAuthHeaders(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxOrDefault(s.Config.MaxBodyBytes, 5<<20))))
	return resp.StatusCode, body, err == nil
}
