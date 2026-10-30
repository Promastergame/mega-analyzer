package vulnscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sendFuzzRequest sends the payload both as form-urlencoded and JSON (if POST/PUT).
func (s *Scanner) sendFuzzRequest(form Form, targetInput string, payload string) (string, []string, []int) {
	var bodies string
	var redirects []string
	var statuses []int

	vals := url.Values{}
	jsonMap := make(map[string]string)

	for _, inp := range form.Inputs {
		val := "test"
		if inp == targetInput {
			val = payload
		}
		vals.Set(inp, val)
		jsonMap[inp] = val
	}

	doReq := func(req *http.Request) {
		req.Header.Set("User-Agent", s.Config.UserAgent)
		resp, err := s.Client.Do(req)
		if err == nil {
			bodyBytes := s.readBody(resp)
			resp.Body.Close()
			bodies += "\n" + string(bodyBytes)
			statuses = append(statuses, resp.StatusCode)
			loc := resp.Header.Get("Location")
			if loc != "" {
				redirects = append(redirects, loc)
			}
		}
	}

	if form.Method == "POST" || form.Method == "PUT" || form.Method == "PATCH" {
		// Form Encoded
		reqForm, _ := http.NewRequest(form.Method, form.Action, strings.NewReader(vals.Encode()))
		reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		doReq(reqForm)

		// JSON Encoded
		jsonData, _ := json.Marshal(jsonMap)
		reqJson, _ := http.NewRequest(form.Method, form.Action, bytes.NewBuffer(jsonData))
		reqJson.Header.Set("Content-Type", "application/json")
		doReq(reqJson)
	} else {
		// GET / DELETE
		u, _ := url.Parse(form.Action)
		u.RawQuery = vals.Encode()
		reqGet, _ := http.NewRequest(form.Method, u.String(), nil)
		doReq(reqGet)
	}

	return bodies, redirects, statuses
}

func (s *Scanner) testXSS(form Form) []Vulnerability {
	var list []Vulnerability
	// Payloads that reflected verbatim during probing are re-tested against the
	// root document afterwards to detect stored (persistent) XSS — one extra
	// request per form instead of one per payload.
	var verified []string

	for _, input := range form.Inputs {
		point := InjectionPoint{Name: input, Location: LocationBody, DataType: InferInputType(input)}
		if point.DataType == TypeUUID || point.DataType == TypeToken {
			continue // opaque identifiers are not browser sinks
		}

		// Phase 1 — benign canary: discover WHETHER and WHERE the input
		// reflects. The detected context drives payload selection and keeps
		// escaped reflections out of the results.
		canary := NewCanary("xss" + input)
		reflCtx := CtxNotReflected
		for _, pr := range s.sendInjectionProbes(form, input, canary) {
			if c := DetectReflectionContext(pr.body, canary, pr.contentType); c != CtxNotReflected {
				reflCtx = c
				break
			}
		}
		if reflCtx == CtxNotReflected {
			continue // no reflection: no XSS surface on this input
		}

		// Phase 2 — context-tailored payloads. A payload only counts when it
		// reflects verbatim (unescaped) in a successful response; WAF/error
		// pages may echo payloads without executing them.
		detected := false
		hitPayload := ""
		for _, pl := range SelectPayloads(point, reflCtx) {
			for _, pr := range s.sendInjectionProbes(form, input, pl) {
				if pr.status >= 400 || !strings.Contains(pr.body, pl) {
					continue
				}
				detected = true
				hitPayload = pl
				break
			}
			if detected {
				break
			}
		}
		if !detected {
			continue
		}
		verified = append(verified, hitPayload)

		severity := SeverityHigh
		name := "Reflected Cross-Site Scripting (XSS)"
		descr := fmt.Sprintf("User input reflects verbatim into the response in %s context without encoding, allowing arbitrary JavaScript execution in victims' browsers.", reflCtx)
		if reflCtx == CtxJSONBody {
			// Reflection inside a JSON envelope requires a client-side sink
			// (innerHTML/eval) to become script execution — report reduced.
			severity = SeverityMedium
			name = "Potential DOM XSS (unsanitized JSON sink)"
			descr = "User input reflects verbatim inside a JSON response body. If any client-side code interpolates this field into the DOM without encoding, it becomes script execution."
		}

		// Snapshot for the confirmation-probe closure (loop variables are reused).
		cf, cinp, cpl := form, input, hitPayload
		list = append(list, Vulnerability{
			ID:          "WS-XSS-001",
			Name:        name,
			Description: descr,
			Severity:    severity,
			URL:         form.Action,
			Parameter:   input,
			Payload:     hitPayload,
			Evidence:    fmt.Sprintf("Payload reflected verbatim in %s context (canary probe: %s)", reflCtx, canary),
			Mitigation:  "Context-aware output encoding (HTML entity, attribute, JavaScript, URL); Content Security Policy with nonces; DOMPurify for dynamic HTML; never interpolate user input into script/JSON contexts.",
			Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
				for _, pr := range sc.sendInjectionProbes(cf, cinp, cpl) {
					if pr.status < 400 && strings.Contains(pr.body, cpl) {
						return true, nil
					}
				}
				return false, nil
			}},
		})
	}

	// Stored XSS verification: a single root-document fetch per form.
	if len(verified) > 0 && s.Target != "" {
		if req, err := http.NewRequest("GET", s.Target, nil); err == nil {
			req.Header.Set("User-Agent", s.Config.UserAgent)
			if resp, err := s.Client.Do(req); err == nil {
				rootBody, rerr := ReadBodyLimited(resp, NeedFull)
				resp.Body.Close()
				if rerr == nil {
					for _, pl := range verified {
						if strings.Contains(string(rootBody), pl) {
							ctarget, cpl := s.Target, pl
							list = append(list, Vulnerability{
								ID:          "WS-XSS-001",
								Name:        "Stored Cross-Site Scripting (XSS)",
								Description: "A payload injected through a form field persists in the root document and executes for every visitor — no reflection of the victim's own request is required.",
								Severity:    SeverityCritical,
								URL:         s.Target,
								Payload:     pl,
								Evidence:    "Injected payload persists in the root document response",
								Mitigation:  "Output encoding on all user-generated content, Content Security Policy, input validation at write time, sanitize stored data before rendering.",
								Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
									req, rerr := http.NewRequest("GET", ctarget, nil)
									if rerr != nil {
										return false, rerr
									}
									req.Header.Set("User-Agent", sc.Config.UserAgent)
									resp, rerr := sc.Client.Do(req)
									if rerr != nil {
										return false, rerr
									}
									defer resp.Body.Close()
									b, rerr := ReadBodyLimited(resp, NeedFull)
									if rerr != nil {
										return false, rerr
									}
									return strings.Contains(string(b), cpl), nil
								}},
							})
							break
						}
					}
				}
			}
		}
	}

	return list
}

// probeResponse is a single response captured during injection probing.
// Unlike sendFuzzRequest (which concatenates bodies across encodings), probes
// keep responses separate so callers can inspect status and Content-Type.
type probeResponse struct {
	status      int
	contentType string
	body        string
}

// sendInjectionProbes sends value to the target input using the form's method
// and returns every response individually. POST/PUT/PATCH forms are
// additionally probed with a proper JSON twin body (application/json).
func (s *Scanner) sendInjectionProbes(form Form, input, value string) []probeResponse {
	var out []probeResponse

	doReq := func(method, target string, body io.Reader, contentType string) {
		req, err := http.NewRequest(method, target, body)
		if err != nil {
			return
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)
		resp, err := s.Client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		b, rerr := ReadBodyLimited(resp, NeedFull)
		if rerr != nil {
			return
		}
		out = append(out, probeResponse{
			status:      resp.StatusCode,
			contentType: resp.Header.Get("Content-Type"),
			body:        string(b),
		})
	}

	if form.Method != "POST" && form.Method != "PUT" && form.Method != "PATCH" {
		u, err := url.Parse(form.Action)
		if err != nil {
			return out
		}
		q := u.Query()
		for _, inp := range form.Inputs {
			if inp == input {
				q.Set(inp, value)
			} else {
				q.Set(inp, "test")
			}
		}
		u.RawQuery = q.Encode()
		doReq(form.Method, u.String(), nil, "")
		return out
	}

	vals := url.Values{}
	jsonObj := map[string]any{}
	for _, inp := range form.Inputs {
		v := "test"
		if inp == input {
			v = value
		}
		vals.Set(inp, v)
		jsonObj[inp] = v
	}
	doReq(form.Method, form.Action, strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")

	if jb, err := json.Marshal(jsonObj); err == nil {
		doReq(form.Method, form.Action, bytes.NewReader(jb), "application/json")
	}
	return out
}

// sqliErrorSignatures are database error fingerprints that indicate query
// structure leaking into a response. All entries are lowercase; matches are
// differential against a benign baseline to avoid false positives on apps
// that display these strings unconditionally.
var sqliErrorSignatures = []string{
	"sql syntax",
	"sqlite3.operationalerror",
	"sqlite_error",
	"unclosed quotation mark",
	"postgresql query failed",
	"syntax error at or near",
	"unterminated quoted string",
	"quoted string not properly terminated",
	"you have an error in your sql",
	"mysql_fetch",
	"ora-01756",
	"microsoft ole db provider for sql server",
	"pg_query()",
	"database error",
}

func (s *Scanner) testSQLi(form Form) []Vulnerability {
	var list []Vulnerability

	for _, input := range form.Inputs {
		point := InjectionPoint{Name: input, Location: LocationBody, DataType: InferInputType(input)}
		payloads := SelectSQLiPayloads(point)
		if len(payloads) == 0 {
			continue
		}

		// Baseline: a benign value against the same input. Anything present
		// here (error strings, redirects) is normal application behavior and
		// must not count as injection evidence.
		baseBody, baseRedirects, _ := s.sendFuzzRequest(form, input, "test")
		baseLower := strings.ToLower(baseBody)

		for _, sqliPayload := range payloads {
			body, redirects, statuses := s.sendFuzzRequest(form, input, sqliPayload)

			// Auth-bypass heuristic: a redirect into a privileged area that
			// only happens with the injection payload (not with benign input).
			for i, status := range statuses {
				if status >= 300 && status < 400 && i < len(redirects) {
					location := redirects[i]
					if isPrivilegedRedirect(location) && !baselineRedirectsTo(baseRedirects, location) {
						cf, cinp, cpl := form, input, sqliPayload
						cBaseline := append([]string{}, baseRedirects...)
						list = append(list, Vulnerability{
							ID:          "WS-SQLI-002",
							Name:        "SQL Injection (SQLi) Auth Bypass",
							Description: "An SQL injection payload caused a redirect into a privileged area that benign input does not reach, indicating the authentication query was manipulated.",
							Severity:    SeverityCritical,
							URL:         form.Action,
							Parameter:   input,
							Evidence:    fmt.Sprintf("Payload triggered a redirect to: %s (benign input does not)", location),
							Payload:     sqliPayload,
							Mitigation:  "Always use parameterized queries or Prepared Statements.",
							Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
								_, redir, stats := sc.sendFuzzRequest(cf, cinp, cpl)
								for j, st := range stats {
									if st >= 300 && st < 400 && j < len(redir) &&
										isPrivilegedRedirect(redir[j]) && !baselineRedirectsTo(cBaseline, redir[j]) {
										return true, nil
									}
								}
								return false, nil
							}},
						})
					}
				}
			}

			bodyLower := strings.ToLower(body)
			for _, sqlErr := range sqliErrorSignatures {
				if strings.Contains(bodyLower, sqlErr) && !strings.Contains(baseLower, sqlErr) {
					cf, cinp, cpl, csig := form, input, sqliPayload, sqlErr
					list = append(list, Vulnerability{
						ID:          "WS-SQLI-001",
						Name:        "SQL Injection (SQLi) Error-Based",
						Description: "A database query error fingerprint appeared only in response to a SQL injection payload, confirming the input is interpolated into a query.",
						Severity:    SeverityHigh,
						URL:         form.Action,
						Parameter:   input,
						Evidence:    fmt.Sprintf("Differential database error fingerprint (absent from benign baseline): %s", sqlErr),
						Payload:     sqliPayload,
						Mitigation:  "Always use parameterized queries or Prepared Statements.",
						Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
							reBody, _, _ := sc.sendFuzzRequest(cf, cinp, cpl)
							return strings.Contains(strings.ToLower(reBody), csig), nil
						}},
					})
					break // one confirmed signature per payload is enough
				}
			}
		}
	}

	return list
}

// isPrivilegedRedirect reports whether a Location header points at an area
// that typically requires authentication.
func isPrivilegedRedirect(location string) bool {
	lower := strings.ToLower(location)
	return strings.Contains(lower, "/admin") || strings.Contains(lower, "/dashboard") || strings.Contains(lower, "/profile")
}

// baselineRedirectsTo checks whether the benign baseline already redirected
// to the same location — if so, the redirect is normal flow, not a bypass.
func baselineRedirectsTo(baseRedirects []string, location string) bool {
	for _, r := range baseRedirects {
		if r == location {
			return true
		}
	}
	return false
}

func (s *Scanner) testLFI(form Form) []Vulnerability {
	var list []Vulnerability
	lfiPayloads := []string{
		"../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../windows/win.ini",
	}

	for _, input := range form.Inputs {
		for _, payload := range lfiPayloads {
			body, _, _ := s.sendFuzzRequest(form, input, payload)

			if strings.Contains(body, "root:x:0:0") || strings.Contains(strings.ToLower(body), "[extensions]") || strings.Contains(strings.ToLower(body), "[fonts]") {
				list = append(list, Vulnerability{
					ID:          "WS-LFI-001",
					Name:        "Local File Inclusion (LFI) / Path Traversal",
					Description: "The application allows an attacker to read arbitrary files on the server.",
					Severity:    SeverityCritical,
					URL:         form.Action,
					Parameter:   input,
					Evidence:    "Successfully read system file contents.",
					Payload:     payload,
					Mitigation:  "Validate and sanitize file paths.",
				})
				break
			}
		}
	}

	return list
}

func (s *Scanner) testOAST(form Form) []Vulnerability {
	var list []Vulnerability

	if !s.Config.LabMode || s.OAST == nil {
		return list
	}

	oastDomain := s.Config.OASTDomain
	oastPort := "8081" // Hardcoded for now based on default Config (Phase 6 fix)

	// Every payload embeds a unique interaction token: a hit is only
	// attributed to the exact form/parameter whose payload carried it.
	// Static paths (/ssrf-hit) would make hits unattributable and let
	// unrelated traffic (other scanners, retries) trigger false positives.
	vulnTypes := []struct {
		name  string
		id    string
		build func(token string) string
	}{
		{"SSRF", "WS-OAST-SSRF", func(tok string) string {
			return fmt.Sprintf("http://%s:%s/%s", oastDomain, oastPort, tok)
		}},
		{"Blind RCE", "WS-OAST-BLIND-RCE", func(tok string) string {
			return fmt.Sprintf("`curl http://%s:%s/%s`", oastDomain, oastPort, tok)
		}},
	}

	for _, vt := range vulnTypes {
		for _, input := range form.Inputs {
			token := s.OAST.IssueToken()
			payload := vt.build(token)
			s.sendFuzzRequest(form, input, payload)

			// Wait for OAST request
			time.Sleep(1500 * time.Millisecond)

			hit, ok := s.OAST.HasTokenHit(token)
			if !ok {
				continue
			}
			list = append(list, Vulnerability{
				ID:          vt.id,
				Name:        fmt.Sprintf("Out-of-Band (OAST) %s", vt.name),
				Description: fmt.Sprintf("The application is vulnerable to %s.", vt.name),
				Severity:    SeverityCritical,
				URL:         form.Action,
				Parameter:   input,
				Evidence:    fmt.Sprintf("OAST Server received interaction carrying payload token %s: %s", token, hit),
				Payload:     payload,
				Mitigation:  "Do not evaluate user input as shell commands (RCE). Use strict allowlists for outbound server requests (SSRF).",
			})
			break // one confirmed hit per vuln type is enough; try the next type
		}
	}

	return list
}
