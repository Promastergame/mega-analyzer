package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// FSMState represents a step in the workflow
type FSMState struct {
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Data        map[string]string `json:"data"`
	Headers     map[string]string `json:"headers"`
	ExtractVars map[string]string `json:"extract_vars"`
	// ExpectStatus asserts the step's HTTP status. Zero means "below 400".
	ExpectStatus int `json:"expect_status,omitempty"`
	// Role selects the credential set: "" and "A" use the primary
	// AuthCookie/AuthBearer, "B" uses AuthCookie2/AuthBearer2. Each role
	// keeps its own cookie jar for the duration of the workflow run.
	Role string `json:"role,omitempty"`
}

// FSMWorkflow represents a multi-step flow (e.g. Add to cart -> Checkout)
type FSMWorkflow struct {
	Name   string     `json:"name"`
	States []FSMState `json:"states"`
}

// WorkflowResult is the machine-readable outcome of one workflow run. Step
// requests are recorded in the Scanner Ledger under "fsm:<name>";
// Interactions carries their IDs so findings can cite the exact exchange.
type WorkflowResult struct {
	Workflow     string            `json:"workflow"`
	StepsOK      int               `json:"steps_ok"`
	StepsTotal   int               `json:"steps_total"`
	Succeeded    bool              `json:"succeeded"`
	Vars         map[string]string `json:"vars,omitempty"`
	Interactions []uint64          `json:"interaction_ids,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// LoadFSMWorkflows loads workflows from a JSON file
func LoadFSMWorkflows(path string) ([]FSMWorkflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var workflows []FSMWorkflow
	err = json.Unmarshal(data, &workflows)
	return workflows, err
}

// ExecuteFSMWorkflow executes a workflow with a bare HTTP client, maintaining
// state (cookies, extracted vars). It is kept for API compatibility; scanner
// runs should prefer (s *Scanner).RunWorkflow, which records interactions in
// the Ledger and resolves roles against the scanner config.
func ExecuteFSMWorkflow(client *http.Client, workflow FSMWorkflow) error {
	s := &Scanner{Client: client, Config: DefaultScannerConfig(), Ledger: NewLedger(1024)}
	result := s.RunWorkflow(context.Background(), workflow)
	if result.Error != "" {
		return fmt.Errorf("workflow %q: %s", workflow.Name, result.Error)
	}
	return nil
}

// RunWorkflow executes every state in order: variable substitution, request,
// variable extraction, status assertion. Steps share per-role cookie jars;
// each request flows through the scanner client (and its gateway), so pacing,
// auth injection and Ledger recording apply uniformly.
func (s *Scanner) RunWorkflow(ctx context.Context, workflow FSMWorkflow) WorkflowResult {
	result := WorkflowResult{Workflow: workflow.Name, StepsTotal: len(workflow.States), Vars: map[string]string{}}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = WithCheckID(ctx, "fsm:"+workflow.Name)
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	jars := map[string]*cookiejar.Jar{}
	vars := map[string]string{}

	for _, state := range workflow.States {
		if err := ctx.Err(); err != nil {
			result.Error = fmt.Sprintf("cancelled before step %q: %v", state.Name, err)
			return result
		}
		stepIDs, stepErr := s.runWorkflowStep(ctx, "fsm:"+workflow.Name, client, jars, vars, state)
		result.Interactions = append(result.Interactions, stepIDs...)
		if stepErr != nil {
			result.Error = stepErr.Error()
			return result
		}
		result.StepsOK++
	}
	result.Succeeded = result.StepsOK == result.StepsTotal
	for k, v := range vars {
		result.Vars[k] = v
	}
	return result
}

func (s *Scanner) runWorkflowStep(ctx context.Context, checkID string, base *http.Client, jars map[string]*cookiejar.Jar, vars map[string]string, state FSMState) ([]uint64, error) {
	s.log("[*] Workflow step %q: %s %s\n", state.Name, state.Method, state.URL)
	before := ledgerCheckIDs(s.Ledger, checkID)

	req, err := buildWorkflowRequest(ctx, vars, state)
	if err != nil {
		return nil, fmt.Errorf("step %q: %w", state.Name, err)
	}
	applyRoleCredentials(s.Config, req, state.Role)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", s.Config.UserAgent)
	}

	client := &http.Client{Transport: base.Transport, Timeout: base.Timeout}
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	jar, err := jarForRole(jars, state.Role)
	if err != nil {
		return nil, fmt.Errorf("step %q: %w", state.Name, err)
	}
	client.Jar = jar

	resp, err := client.Do(req)
	if err != nil {
		return ledgerDelta(s.Ledger, checkID, before), fmt.Errorf("step %q: request failed: %w", state.Name, err)
	}
	defer resp.Body.Close()
	maxBody := s.Config.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 5 * 1024 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
	if err != nil {
		return ledgerDelta(s.Ledger, checkID, before), fmt.Errorf("step %q: read body: %w", state.Name, err)
	}
	if err := extractWorkflowVars(vars, state.ExtractVars, resp, body); err != nil {
		return ledgerDelta(s.Ledger, checkID, before), fmt.Errorf("step %q: %w", state.Name, err)
	}
	if want := state.ExpectStatus; want != 0 {
		if resp.StatusCode != want {
			return ledgerDelta(s.Ledger, checkID, before), fmt.Errorf("step %q: status %d, want %d", state.Name, resp.StatusCode, want)
		}
	} else if resp.StatusCode >= 400 {
		return ledgerDelta(s.Ledger, checkID, before), fmt.Errorf("step %q: status %d", state.Name, resp.StatusCode)
	}
	return ledgerDelta(s.Ledger, checkID, before), nil
}

func ledgerCheckIDs(ledger *Ledger, checkID string) []uint64 {
	if ledger == nil {
		return nil
	}
	var out []uint64
	for _, in := range ledger.FindByCheck(checkID) {
		out = append(out, in.ID)
	}
	return out
}

func ledgerDelta(ledger *Ledger, checkID string, before []uint64) []uint64 {
	after := ledgerCheckIDs(ledger, checkID)
	if len(after) <= len(before) {
		return nil
	}
	return after[len(before):]
}

// buildWorkflowRequest renders one state: {{var}} substitution, then query
// params for bodyless methods and form-encoded bodies otherwise.
func buildWorkflowRequest(ctx context.Context, vars map[string]string, state FSMState) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(state.Method))
	if method == "" {
		method = http.MethodGet
	}
	rawURL := substituteVars(state.URL, vars)
	if rawURL == "" {
		return nil, fmt.Errorf("empty URL")
	}
	data := make(map[string]string, len(state.Data))
	for k, v := range state.Data {
		data[k] = substituteVars(v, vars)
	}
	var body io.Reader
	target := rawURL
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions:
		if len(data) > 0 {
			u, err := url.Parse(rawURL)
			if err != nil {
				return nil, fmt.Errorf("bad URL %q: %w", rawURL, err)
			}
			q := u.Query()
			for k, v := range data {
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()
			target = u.String()
		}
	default:
		form := url.Values{}
		for k, v := range data {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range state.Headers {
		req.Header.Set(k, substituteVars(v, vars))
	}
	return req, nil
}

func substituteVars(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// applyRoleCredentials pins the step to one identity. Role "" and "A" keep
// the gateway-injected primary credentials; role "B" sets the secondary
// identity explicitly (the gateway never overrides present headers).
func applyRoleCredentials(cfg ScannerConfig, req *http.Request, role string) {
	if !strings.EqualFold(strings.TrimSpace(role), "B") {
		return
	}
	if cfg.AuthCookie2 != "" {
		req.Header.Set("Cookie", cfg.AuthCookie2)
	}
	if cfg.AuthBearer2 != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.AuthBearer2)
	}
}

func jarForRole(jars map[string]*cookiejar.Jar, role string) (*cookiejar.Jar, error) {
	key := strings.ToUpper(strings.TrimSpace(role))
	if key == "" {
		key = "A"
	}
	if jar, ok := jars[key]; ok {
		return jar, nil
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie jar: %w", err)
	}
	jars[key] = jar
	return jar, nil
}

// extractWorkflowVars supports four extractor forms:
//   - "status"            → response status code
//   - "header:<Name>"     → response header value
//   - "regex:<pattern>"   → first capture group (or full match) in the body
//   - "json:<RFC6901>"    → scalar at the JSON pointer in a JSON body
func extractWorkflowVars(vars map[string]string, specs map[string]string, resp *http.Response, body []byte) error {
	for name, spec := range specs {
		switch {
		case spec == "status":
			vars[name] = strconv.Itoa(resp.StatusCode)
		case strings.HasPrefix(spec, "header:"):
			vars[name] = resp.Header.Get(strings.TrimPrefix(spec, "header:"))
		case strings.HasPrefix(spec, "regex:"):
			re, err := regexp.Compile(strings.TrimPrefix(spec, "regex:"))
			if err != nil {
				return fmt.Errorf("extract %q: bad regex: %w", name, err)
			}
			m := re.FindStringSubmatch(string(body))
			if m == nil {
				return fmt.Errorf("extract %q: pattern did not match", name)
			}
			if len(m) > 1 {
				vars[name] = m[1]
			} else {
				vars[name] = m[0]
			}
		case strings.HasPrefix(spec, "json:"):
			var data any
			if err := json.Unmarshal(body, &data); err != nil {
				return fmt.Errorf("extract %q: body is not JSON: %w", name, err)
			}
			value, err := jsonPointer(data, strings.TrimPrefix(spec, "json:"))
			if err != nil {
				return fmt.Errorf("extract %q: %w", name, err)
			}
			vars[name] = fmt.Sprint(value)
		default:
			return fmt.Errorf("extract %q: unknown extractor %q (want status, header:, regex: or json:)", name, spec)
		}
	}
	return nil
}
