package vulnscan

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// idParamRe recognizes parameter names likely to carry object identifiers.
// Compiled once: testIDOR evaluates it for every form input.
var idParamRe = regexp.MustCompile(`(?i)(id|user_id|doc_id|account_id|profile_id|order_id)`)

// identity selects which credential set a probe uses. Role A is the primary
// (gateway-injected) identity, role B the configured secondary identity.
type identity string

const (
	identityA identity = "A"
	identityB identity = "B"
)

// hasSecondIdentity reports whether a differential cross-role check is
// possible. Without a second identity ownership cannot be proven: a
// differing response for another ID may be public data.
func (s *Scanner) hasSecondIdentity() bool {
	return s.Config.AuthCookie2 != "" || s.Config.AuthBearer2 != ""
}

// testIDOR attempts to detect Insecure Direct Object Reference (IDOR)
// vulnerabilities by manipulating parameters that look like IDs.
//
// With two configured identities it proves cross-role access: the same
// object fetched as another user must be rejected. That verdict is reported
// High with Verification "cross-role". With a single identity only the
// classic mutated-ID heuristic applies; it is reported Medium with
// Verification "heuristic-only" because object ownership is unproven.
func (s *Scanner) testIDOR(form Form) []Vulnerability {
	var list []Vulnerability

	for _, input := range form.Inputs {
		if !idParamRe.MatchString(input) {
			continue
		}
		point := injectionPointFor(form, input)

		// Establish a baseline request with a known value: prefer the
		// captured original so sibling parameters stay valid.
		baselineID := point.Original
		if baselineID == "" {
			baselineID = "1"
		}
		baselineBody, baselineStatus, baselineIDs := s.sendIDORProbe(form, point, baselineID, identityA)
		if baselineStatus != 200 {
			continue // If baseline fails, we can't reliably test IDOR
		}

		if s.hasSecondIdentity() {
			if v, ok := s.testIDORCrossRole(form, point, input, baselineID, baselineBody, baselineIDs); ok {
				list = append(list, v)
			}
			continue
		}

		// Single identity: mutate the ID and compare. A different valid
		// response is only a hint — the object may be public.
		testIDInt, err := strconv.Atoi(baselineID)
		if err != nil {
			continue // Only testing numeric IDs for now
		}
		mutatedID := strconv.Itoa(testIDInt + 1)

		mutatedBody, mutatedStatus, mutatedIDs := s.sendIDORProbe(form, point, mutatedID, identityA)

		if mutatedStatus == 200 && mutatedBody != baselineBody && !looksLikeError(mutatedBody) {
			list = append(list, Vulnerability{
				ID:             "WS-IDOR-001",
				Name:           "Potential Insecure Direct Object Reference (IDOR)",
				Description:    fmt.Sprintf("Manipulating the '%s' parameter (from %s to %s) returned a different, seemingly valid response. Ownership is unproven: the object may be public or shared.", input, baselineID, mutatedID),
				Severity:       SeverityMedium,
				URL:            form.Action,
				Parameter:      input,
				Payload:        mutatedID,
				Evidence:       fmt.Sprintf("Status code 200 returned for mutated ID. Body differs from baseline (length %d vs %d). Single identity only — confirm with a second account.", len(mutatedBody), len(baselineBody)),
				Verification:   "heuristic-only",
				Mitigation:     "Implement proper access control checks on the server-side to ensure the authenticated user has permission to access the requested resource ID.",
				InteractionIDs: append(append([]uint64{}, baselineIDs...), mutatedIDs...),
			})
		}
	}

	return list
}

// testIDORCrossRole fetches the baseline object as the secondary identity. A
// 200 with the same body proves user B reads user A's object. A 401/403
// proves access control works and yields no finding.
func (s *Scanner) testIDORCrossRole(form Form, point InjectionPoint, input, baselineID, baselineBody string, baselineIDs []uint64) (Vulnerability, bool) {
	otherBody, otherStatus, otherIDs := s.sendIDORProbe(form, point, baselineID, identityB)
	ids := append(append([]uint64{}, baselineIDs...), otherIDs...)
	switch {
	case otherStatus == http.StatusUnauthorized || otherStatus == http.StatusForbidden:
		return Vulnerability{}, false
	case otherStatus == 200 && otherBody == baselineBody && !looksLikeError(otherBody):
		return Vulnerability{
			ID:             "WS-IDOR-001",
			Name:           "Insecure Direct Object Reference (IDOR)",
			Description:    fmt.Sprintf("Object '%s=%s' fetched as the primary identity is also readable as the secondary identity (identical %d-byte response). Cross-role access is proven.", input, baselineID, len(baselineBody)),
			Severity:       SeverityHigh,
			URL:            form.Action,
			Parameter:      input,
			Payload:        baselineID,
			Evidence:       fmt.Sprintf("Secondary identity received HTTP 200 with a body identical to the primary identity (length %d).", len(baselineBody)),
			Verification:   "cross-role",
			Mitigation:     "Enforce server-side ownership checks: the authenticated user must own, or be explicitly granted, every requested resource ID.",
			InteractionIDs: ids,
		}, true
	default:
		s.log("[*] IDOR cross-role probe for %q inconclusive (secondary status %d)\n", input, otherStatus)
		return Vulnerability{}, false
	}
}

// sendIDORProbe issues one IDOR probe with a single mutated parameter. When
// the form carries its captured request template, siblings keep their
// original values; otherwise it falls back to the legacy rebuilt form.
func (s *Scanner) sendIDORProbe(form Form, point InjectionPoint, payload string, role identity) (string, int, []uint64) {
	var before []uint64
	if s.Ledger != nil {
		for _, in := range s.Ledger.FindByCheck("idor") {
			before = append(before, in.ID)
		}
	}
	var req *http.Request
	if form.Request != nil && point.Name != "" {
		mutated, err := MutateRequest(WithCheckID(s.context(), "idor"), form.Request, point, payload)
		if err != nil {
			return "", 0, nil
		}
		req = applyIdentity(mutated, s.Config, role)
	} else {
		req = s.legacyIDORRequest(form, point.Name, payload, role)
		if req == nil {
			return "", 0, nil
		}
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", 0, nil
	}
	defer resp.Body.Close()

	bodyBytes := s.readBody(resp)
	var ids []uint64
	if s.Ledger != nil {
		seen := make(map[uint64]bool, len(before))
		for _, id := range before {
			seen[id] = true
		}
		for _, in := range s.Ledger.FindByCheck("idor") {
			if !seen[in.ID] {
				ids = append(ids, in.ID)
			}
		}
	}
	return string(bodyBytes), resp.StatusCode, ids
}

// applyIdentity pins an already-built request to one identity. Role A keeps
// gateway injection; role B sets the secondary credentials explicitly.
func applyIdentity(req *http.Request, cfg ScannerConfig, role identity) *http.Request {
	if role != identityB {
		return req
	}
	if cfg.AuthCookie2 != "" {
		req.Header.Set("Cookie", cfg.AuthCookie2)
	}
	if cfg.AuthBearer2 != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.AuthBearer2)
	}
	return req
}

// injectionPointFor resolves the captured point for an input name so probes
// mutate exactly one occurrence. Without a captured template it synthesizes
// a query/body point matching the legacy form encoding.
func injectionPointFor(form Form, input string) InjectionPoint {
	for _, p := range form.Points {
		if p.Name == input {
			return p
		}
	}
	loc := LocationBody
	if strings.ToUpper(form.Method) == "" || strings.ToUpper(form.Method) == http.MethodGet {
		loc = LocationQueryParam
	}
	return InjectionPoint{Name: input, Location: loc, DataType: InferInputType(input)}
}

func looksLikeError(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "error") || strings.Contains(lower, "not found")
}

func (s *Scanner) legacyIDORRequest(form Form, targetInput string, payload string, role identity) *http.Request {
	vals := url.Values{}
	for _, inp := range form.Inputs {
		val := "test"
		if inp == targetInput {
			val = payload
		}
		vals.Set(inp, val)
	}

	ctx := WithCheckID(s.context(), "idor")
	var req *http.Request
	if form.Method == "POST" || form.Method == "PUT" || form.Method == "PATCH" {
		req, _ = http.NewRequestWithContext(ctx, form.Method, form.Action, strings.NewReader(vals.Encode()))
		if req == nil {
			return nil
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		u, _ := url.Parse(form.Action)
		if u == nil {
			return nil
		}
		u.RawQuery = vals.Encode()
		req, _ = http.NewRequestWithContext(ctx, form.Method, u.String(), nil)
		if req == nil {
			return nil
		}
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	return applyIdentity(req, s.Config, role)
}
