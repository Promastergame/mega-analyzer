package vulnscan

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/secrets"
)

// Severity defines the vulnerability risk level
type Severity string

// Package-level compiled regexes for HTML parsing (compiled once, reused across calls).
var (
	reForm      = regexp.MustCompile(`(?i)<form[^>]*>([\s\S]*?)<\/form>`)
	reAction    = regexp.MustCompile(`(?i)action=["']([^"']*)["']`)
	reMethod    = regexp.MustCompile(`(?i)method=["']([^"']*)["']`)
	reInput     = regexp.MustCompile(`(?i)<(input|textarea)[^>]*name=["']([^"']*)["']`)
	reEnctype   = regexp.MustCompile(`(?i)enctype=["']([^"']*)["']`)
	reLink      = regexp.MustCompile(`(?i)<a[^>]*href=["']([^"']+)["']`)
	reLinkQuery = regexp.MustCompile(`(?i)<a[^>]*href=["']([^"']*\?[^"']*)["']`)
)

// cgnatNet is the IANA Carrier-Grade NAT block (RFC 6598), cached at package init.
var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Vulnerability represents a discovered issue
type Vulnerability struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	URL            string   `json:"url"`
	Parameter      string   `json:"parameter,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Payload        string   `json:"payload,omitempty"`
	Mitigation     string   `json:"mitigation"`
	Verification   string   `json:"verification,omitempty"`
	InteractionIDs []uint64 `json:"interaction_ids,omitempty"`

	// Probe, when set on a High/Critical finding, lets the confirmation pass
	// retransmit the trigger request and verify the evidence reproduces
	// before reporting. Not serialized.
	Probe *ReplayProbe `json:"-"`
}

// Form represents an HTML form extracted during crawling
type Form struct {
	Action  string
	Method  string
	Enctype string
	Inputs  []string
	Request *BaseRequest
	Points  []InjectionPoint
}

// Scanner handles active scanning of web targets
type Scanner struct {
	Client     *http.Client
	Target     string
	BaseURL    *url.URL
	Config     ScannerConfig
	Throttle   *PIDController
	OAST       *OASTServer
	LogFunc    func(string)
	Gateway    *RequestGateway
	Ledger     *Ledger
	Findings   []Finding
	Workflows  []WorkflowResult
	Warnings   []string
	runMu      sync.Mutex
	runContext context.Context
	runCancel  context.CancelCauseFunc
}

func (s *Scanner) log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if s.LogFunc != nil {
		s.LogFunc(msg)
	}
}

// NewScanner constructs a new active web scanner. All traffic flows through
// the RequestGateway, which owns rate pacing, auth injection, scope
// enforcement, telemetry, and backpressure feedback.
func NewScanner(target string) (*Scanner, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "http"
	}
	s := &Scanner{
		Client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Target:  parsed.String(),
		BaseURL: parsed,
		Config:  DefaultScannerConfig(),
	}
	s.Gateway = NewRequestGateway(s)
	s.Client.Transport = s.Gateway
	s.Ledger = NewLedger(10000)
	return s, nil
}

// Scan performs active vulnerability scanning against the target
func (s *Scanner) Scan() ([]Vulnerability, error) {
	if !s.Config.IOwnThisTarget {
		return nil, fmt.Errorf("safety gate: --i-own-this-target is required to run active scans")
	}
	runCtx := s.ensureRun(context.Background())
	defer s.stopRun(nil)

	var vulns []Vulnerability

	s.log("[*] Initiating Web Security Scan on target: %s\n", s.Target)

	s.Throttle = NewPIDController(200.0, s.Config.MaxRPS)

	if s.Config.LabMode {
		s.OAST = NewOASTServer(s.Config)
		s.OAST.Start()
		defer s.OAST.Stop()

		// Run Desync test
		if TestHTTPDesync(s.Target, s.Config) {
			vulns = append(vulns, Vulnerability{
				ID:          "WS-DESYNC-001",
				Name:        "HTTP Request Smuggling (Desync)",
				Description: "Target is vulnerable to HTTP request smuggling over raw TCP.",
				Severity:    SeverityCritical,
				URL:         s.Target,
				Mitigation:  "Configure frontend and backend servers to interpret HTTP headers identically, or use HTTP/2.",
			})
		}
	}

	// Step 1: Request root page
	req, err := http.NewRequest("GET", s.Target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for target: %w", err)
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	resp, err := s.Client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("failed to reach target: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	body := string(bodyBytes)

	// Check HTTP Headers
	vulns = append(vulns, s.checkSecurityHeaders(resp.Header)...)
	vulns = append(vulns, s.RunDynamicHeaderRules(resp.Header)...)

	// Cookie Security Flags
	vulns = append(vulns, s.checkCookieFlags(resp)...)

	// JWT Checks (Headers & Body)
	vulns = append(vulns, s.checkJWTs(resp, body)...)

	// Passive Secret Scanning (Depth 0)
	vulns = append(vulns, s.detectSecrets(body, s.Target)...)
	vulns = append(vulns, s.checkPassiveWebExtras(body, s.Target)...)
	vulns = append(vulns, s.checkJSSupplyChain(body, s.Target)...)
	vulns = append(vulns, s.RunDynamicPassiveRules(body, s.Target)...)

	// Step 2: Crawl and extract forms (Depth 0)
	forms := s.extractForms(body, s.Target)

	// Discover internal links for Depth 1 crawling
	linkRe := reLink
	matches := linkRe.FindAllStringSubmatch(body, -1)

	visited := make(map[string]bool)
	visited[s.Target] = true
	var discoveredLinks []string

	for _, m := range matches {
		href := m[1]
		parsedUrl, err := url.Parse(href)
		if err != nil {
			continue
		}

		// Resolve absolute URL
		absURL := s.BaseURL.ResolveReference(parsedUrl)

		// Only follow links on the same host
		if absURL.Host == s.BaseURL.Host && !visited[absURL.String()] {
			visited[absURL.String()] = true
			discoveredLinks = append(discoveredLinks, absURL.String())
		}
	}

	// Crawl Depth 1 links
	for _, link := range discoveredLinks {
		req, err := http.NewRequest("GET", link, nil)
		if err != nil {
			s.log("[-] Skipping link %s: failed to build request: %v\n", link, err)
			continue
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)

		resp, err := s.Client.Do(req)

		if err == nil {
			linkBodyBytes, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
			if err == nil {
				linkBody := string(linkBodyBytes)
				forms = append(forms, s.extractForms(linkBody, link)...)
				vulns = append(vulns, s.detectSecrets(linkBody, link)...)
				vulns = append(vulns, s.checkPassiveWebExtras(linkBody, link)...)
				vulns = append(vulns, s.checkJSSupplyChain(linkBody, link)...)
				vulns = append(vulns, s.RunDynamicPassiveRules(linkBody, link)...)
			}
			resp.Body.Close()
		}
	}

	// Remove duplicate forms
	var uniqueForms []Form
	seenForms := make(map[string]bool)
	for _, f := range forms {
		key := fmt.Sprintf("%s|%s|%v", f.Action, f.Method, f.Inputs)
		if !seenForms[key] {
			seenForms[key] = true
			uniqueForms = append(uniqueForms, f)
		}
	}
	forms = uniqueForms

	// DOM-based form extraction via chromedp (Depth 0 only for speed)
	domForms, domHtml, domErr := ExtractDOMForms(runCtx, s.Target, s.Config.Timeout)
	if domErr == nil {
		forms = append(forms, domForms...)

		// Parse the rendered HTML for forms that angular/react generated
		if domHtml != "" {
			forms = append(forms, s.extractForms(domHtml, s.Target)...)
			vulns = append(vulns, s.detectSecrets(domHtml, s.Target)...)
		}
	} else {
		s.log("[-] DOM Extraction failed: %v\n", domErr)
	}

	s.log("[+] Crawling complete. Discovered %d HTML form(s) and endpoints on root and depth-1 pages.\n", len(forms))

	// Step 3: Fuzz discovered forms (Concurrent with Worker Pool)
	vulnChan := make(chan []Vulnerability, len(forms))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Config.MaxWorkers)

	for i, form := range forms {
		wg.Add(1)
		go func(idx int, f Form) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			s.log("[*] Fuzzing Form #%d (Action: %s, Method: %s, Inputs: %v)\n", idx+1, f.Action, f.Method, f.Inputs)

			// The core injection checks (XSS, SQLi, LFI, IDOR, HPP, prototype
			// pollution, upload, SSTI, SSRF, race) are registered in the
			// check registry and run via Engine.RunActiveChecks below, which
			// gives them invasiveness gating, telemetry, dedup and
			// correlation. Only checks with external state dependencies stay
			// on this path.
			var localVulns []Vulnerability

			// Try to extract cookies for CSRF check
			var cookieStrs []string
			for _, cookie := range resp.Cookies() {
				cookieStrs = append(cookieStrs, cookie.String())
			}
			localVulns = append(localVulns, s.testCSRF(f, cookieStrs)...)

			localVulns = append(localVulns, s.RunDynamicFuzzRules(f)...)

			// Phase 4: Blind OAST checks (SSRF/RCE)
			if s.Config.LabMode && s.OAST != nil {
				localVulns = append(localVulns, s.testOAST(f)...)
			}

			vulnChan <- localVulns
		}(i, form)
	}

	wg.Wait()
	close(vulnChan)

	for v := range vulnChan {
		vulns = append(vulns, v...)
	}

	// All registered checks (including the migrated form fuzzers) run through
	// the structured attack-surface pipeline, which applies invasiveness
	// gating, telemetry, deduplication and correlation.
	activeFindings, activeErr := NewEngine(s).RunActiveChecks(runCtx, forms)
	if activeErr != nil {
		s.log("[-] Active injection pipeline failed: %v\n", activeErr)
	} else {
		for _, finding := range activeFindings {
			vulns = append(vulns, finding.Vulnerability)
		}
	}

	// Step 4: Active checks — CORS, Open Redirect, Sensitive Files
	s.log("[*] Running CORS misconfiguration checks...\n")
	vulns = append(vulns, s.checkCORS()...)

	s.log("[*] Running Open Redirect checks...\n")
	vulns = append(vulns, s.checkOpenRedirect()...)

	s.log("[*] Probing sensitive files and endpoints...\n")
	vulns = append(vulns, s.probeSensitiveFiles()...)

	s.log("[*] Running GraphQL, API, Host Header, and Cache Poisoning checks...\n")
	vulns = append(vulns, s.runDeepAPIChecks()...)

	s.log("[*] Running SSTI header injection checks...\n")
	vulns = append(vulns, s.checkSSTIInHeaders()...)

	// Check FSM Workflows if configured
	if s.Config.FSMConfigPath != "" {
		workflows, fsmErr := LoadFSMWorkflows(s.Config.FSMConfigPath)
		if fsmErr == nil {
			for _, wf := range workflows {
				result := s.RunWorkflow(runCtx, wf)
				s.Workflows = append(s.Workflows, result)
				if result.Error != "" {
					s.log("[-] Workflow %q failed: %s\n", wf.Name, result.Error)
				} else {
					s.log("[+] Workflow %q completed: %d/%d steps\n", wf.Name, result.StepsOK, len(wf.States))
				}
			}
		} else {
			s.log("[-] Failed to load FSM config: %v\n", fsmErr)
		}
	}

	return s.runConfirmationPass(vulns), nil
}

// ScanFromRequest performs a targeted scan using a pre-built *http.Request
// (e.g. imported from a curl command or a raw HTTP file).
// It executes the request, runs all header/body/cookie passive checks,
// then runs active checks (CORS, redirect, sensitive probes) against the same origin.
func (s *Scanner) ScanFromRequest(req *http.Request) ([]Vulnerability, error) {
	if !s.Config.IOwnThisTarget {
		return nil, fmt.Errorf("safety gate: --i-own-this-target is required to run active scans")
	}

	// Override target to the request host so active checks point at the right origin
	s.BaseURL = req.URL
	s.Target = req.URL.Scheme + "://" + req.URL.Host + req.URL.RequestURI()

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", s.Config.UserAgent)
	}

	s.Throttle = NewPIDController(200.0, s.Config.MaxRPS)

	var vulns []Vulnerability

	s.log("[*] Executing imported request: %s %s\n", req.Method, req.URL.String())

	resp, err := s.Client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	body := string(bodyBytes)

	// Passive checks
	vulns = append(vulns, s.checkSecurityHeaders(resp.Header)...)
	vulns = append(vulns, s.RunDynamicHeaderRules(resp.Header)...)
	vulns = append(vulns, s.checkCookieFlags(resp)...)
	vulns = append(vulns, s.checkJWTs(resp, body)...)
	vulns = append(vulns, s.detectSecrets(body, s.Target)...)
	vulns = append(vulns, s.checkPassiveWebExtras(body, s.Target)...)
	vulns = append(vulns, s.checkJSSupplyChain(body, s.Target)...)
	vulns = append(vulns, s.RunDynamicPassiveRules(body, s.Target)...)

	// Active checks against same origin
	vulns = append(vulns, s.checkCORS()...)
	vulns = append(vulns, s.checkOpenRedirect()...)
	vulns = append(vulns, s.probeSensitiveFiles()...)
	vulns = append(vulns, s.runDeepAPIChecks()...)
	vulns = append(vulns, s.checkSSTIInHeaders()...)

	s.log("[+] ScanFromRequest complete. %d findings.\n", len(vulns))
	return s.runConfirmationPass(vulns), nil
}

// runDeepAPIChecks executes the GraphQL/API/OAuth/injection/timing check
// family shared between Scan and ScanFromRequest.
func (s *Scanner) runDeepAPIChecks() []Vulnerability {
	var vulns []Vulnerability
	vulns = append(vulns, s.checkGraphQL()...)
	vulns = append(vulns, s.checkAPI()...)
	vulns = append(vulns, s.checkAPIBOLA()...)
	vulns = append(vulns, s.checkAPIDeserialization()...)
	vulns = append(vulns, s.checkHostHeaderInjection()...)
	vulns = append(vulns, s.checkCachePoisoning()...)
	vulns = append(vulns, s.checkCacheDeception()...)
	vulns = append(vulns, s.checkOAuthPKCE()...)
	vulns = append(vulns, s.checkOAuthRedirectURI()...)
	vulns = append(vulns, s.checkTimingOracle()...)
	vulns = append(vulns, s.checkReDoS()...)
	vulns = append(vulns, s.checkH2CSmuggling()...)
	vulns = append(vulns, s.checkNoSQLInjection()...)
	vulns = append(vulns, s.checkLDAPInjection()...)
	vulns = append(vulns, s.checkBlindXPath()...)
	vulns = append(vulns, s.checkMassAssignment()...)
	return vulns
}

// ScanHTMLBody performs passive-only analysis of a provided HTML body string.
// No active requests are made. Useful for analyzing captured/saved responses.
func (s *Scanner) ScanHTMLBody(htmlBody, sourceURL string) []Vulnerability {
	var vulns []Vulnerability

	vulns = append(vulns, s.detectSecrets(htmlBody, sourceURL)...)
	vulns = append(vulns, s.checkPassiveWebExtras(htmlBody, sourceURL)...)
	vulns = append(vulns, s.checkJSSupplyChain(htmlBody, sourceURL)...)
	vulns = append(vulns, s.RunDynamicPassiveRules(htmlBody, sourceURL)...)

	return vulns
}

// isPrivateIP returns true if ip is in a private or link-local range.
func isPrivateIP(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Carrier-grade NAT: 100.64.0.0/10 (RFC 6598)
	return cgnatNet != nil && cgnatNet.Contains(ip)
}

func (s *Scanner) checkSecurityHeaders(headers http.Header) []Vulnerability {
	var list []Vulnerability

	checks := []struct {
		header      string
		severity    Severity
		name        string
		description string
		mitigation  string
	}{
		{
			header:      "Content-Security-Policy",
			severity:    SeverityHigh,
			name:        "Missing Content Security Policy (CSP)",
			description: "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
			mitigation:  "Configure your web server to return a Content-Security-Policy HTTP header containing rules for trusted sources.",
		},
		{
			header:      "X-Frame-Options",
			severity:    SeverityMedium,
			name:        "Missing X-Frame-Options Header",
			description: "The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.",
			mitigation:  "Set the X-Frame-Options header to 'DENY' or 'SAMEORIGIN' to protect against Clickjacking.",
		},
		{
			header:      "X-Content-Type-Options",
			severity:    SeverityLow,
			name:        "Missing X-Content-Type-Options Header",
			description: "The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should be followed and not be changed.",
			mitigation:  "Set the X-Content-Type-Options header to 'nosniff' to disable MIME-type sniffing.",
		},
		{
			header:      "Strict-Transport-Security",
			severity:    SeverityHigh,
			name:        "Missing Strict-Transport-Security (HSTS) Header",
			description: "The HTTP Strict-Transport-Security response header informs browsers that the site should only be accessed using HTTPS, preventing protocol-downgrade attacks and cookie hijacking.",
			mitigation:  "Add the Strict-Transport-Security header with a suitable max-age, e.g. 'max-age=31536000; includeSubDomains; preload'.",
		},
		{
			header:      "Referrer-Policy",
			severity:    SeverityLow,
			name:        "Missing Referrer-Policy Header",
			description: "The Referrer-Policy header controls how much referrer information is included with requests, preventing sensitive URL leakage to third parties.",
			mitigation:  "Set the Referrer-Policy header to 'no-referrer' or 'strict-origin-when-cross-origin'.",
		},
		{
			header:      "Permissions-Policy",
			severity:    SeverityLow,
			name:        "Missing Permissions-Policy Header",
			description: "The Permissions-Policy header allows a site to control which browser features and APIs can be used in the browser, limiting the attack surface for malicious content.",
			mitigation:  "Set the Permissions-Policy header to restrict unused browser features, e.g. 'geolocation=(), microphone=(), camera=()'.",
		},
	}

	for _, check := range checks {
		if headers.Get(check.header) == "" {
			list = append(list, Vulnerability{
				ID:          "WS-HDR-" + strings.ReplaceAll(check.header, "-", ""),
				Name:        check.name,
				Description: check.description,
				Severity:    check.severity,
				URL:         s.Target,
				Mitigation:  check.mitigation,
			})
		}
	}

	return list
}

func (s *Scanner) extractForms(html string, pageURL string) []Form {
	var forms []Form

	pageParsed, err := url.Parse(pageURL)
	if err != nil {
		pageParsed = s.BaseURL
	}

	// Simple regex for forms extraction
	formMatches := reForm.FindAllStringSubmatch(html, -1)
	for _, match := range formMatches {
		formTag := match[0]
		formInner := match[1]

		action := ""
		if actMatch := reAction.FindStringSubmatch(formTag); len(actMatch) > 1 {
			action = actMatch[1]
		}

		method := "GET"
		if methMatch := reMethod.FindStringSubmatch(formTag); len(methMatch) > 1 {
			method = strings.ToUpper(methMatch[1])
		}

		enctype := "application/x-www-form-urlencoded"
		if encMatch := reEnctype.FindStringSubmatch(formTag); len(encMatch) > 1 {
			enctype = strings.ToLower(encMatch[1])
		}

		// Resolve absolute action URL against the page where it was found
		actionURL, err := pageParsed.Parse(action)
		if err == nil {
			action = actionURL.String()
		} else {
			action = pageURL
		}

		// Extract inputs
		var inputs []string
		inputMatches := reInput.FindAllStringSubmatch(formInner, -1)
		seen := make(map[string]bool)
		for _, inpMatch := range inputMatches {
			name := inpMatch[2]
			if !seen[name] {
				seen[name] = true
				inputs = append(inputs, name)
			}
		}

		forms = append(forms, Form{
			Action:  action,
			Method:  method,
			Enctype: enctype,
			Inputs:  inputs,
		})
	}

	// Also extract generic links with query parameters to test for GET parameters
	linkMatches := reLinkQuery.FindAllStringSubmatch(html, -1)
	for _, match := range linkMatches {
		href := match[1]
		parsedUrl, err := url.Parse(href)
		if err != nil {
			continue
		}

		action := ""
		actionURL, err := s.BaseURL.Parse(parsedUrl.Path)
		if err == nil {
			action = actionURL.String()
		} else {
			action = s.Target
		}

		var inputs []string
		for key := range parsedUrl.Query() {
			inputs = append(inputs, key)
		}

		if len(inputs) > 0 {
			forms = append(forms, Form{
				Action:  action,
				Method:  "GET",
				Enctype: "application/x-www-form-urlencoded",
				Inputs:  inputs,
			})
		}
	}

	return forms
}

// secretPattern pairs a precompiled broad/legacy secret detector with its
// display name. The slice keeps evaluation order deterministic (map
// iteration would randomize finding order between runs).
type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"AWS Access Key", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
	{"GitHub Token", regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`)},
	{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)},
	{"Private Key", regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"Generic Secret", regexp.MustCompile(`(?i)(password|secret|api_key|token)["'\s:=]+(["'][a-zA-Z0-9_\-\+]{8,}["'])`)},
}

func (s *Scanner) detectSecrets(body string, targetUrl string) []Vulnerability {
	var list []Vulnerability

	for _, sf := range secrets.DetectProviders(body, targetUrl) {
		list = append(list, Vulnerability{
			ID:          "WS-" + strings.ToUpper(strings.ReplaceAll(sf.RuleID, "/", "-")),
			Name:        fmt.Sprintf("Information Disclosure: %s", sf.Name),
			Description: fmt.Sprintf("A provider-specific credential (%s) was found in the HTTP response body.", sf.Provider),
			Severity:    Severity(strings.ToUpper(sf.Severity)),
			URL:         targetUrl,
			Evidence:    fmt.Sprintf("Match found: %s", sf.MaskedValue),
			Mitigation:  sf.Remediation,
		})
	}

	// Broad/legacy secret patterns. Provider-specific hits above are masked
	// and richer; these are kept for backward-compatible web findings.
	for _, sp := range secretPatterns {
		matches := sp.re.FindAllString(body, -1)

		// Deduplicate matches
		uniqueMatches := make(map[string]bool)
		for _, m := range matches {
			uniqueMatches[m] = true
		}

		for m := range uniqueMatches {
			// Limit the preview size
			evidence := m
			if len(evidence) > 50 {
				evidence = evidence[:50] + "..."
			}

			list = append(list, Vulnerability{
				ID:          fmt.Sprintf("WS-SECRET-%s", strings.ReplaceAll(strings.ToUpper(sp.name), " ", "-")),
				Name:        fmt.Sprintf("Information Disclosure: %s", sp.name),
				Description: fmt.Sprintf("A hardcoded secret (%s) was found in the HTTP response body.", sp.name),
				Severity:    SeverityCritical,
				URL:         targetUrl,
				Evidence:    fmt.Sprintf("Match found: %s", evidence),
				Mitigation:  "Remove hardcoded secrets from code and configuration files. Use a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager) and inject them via environment variables.",
			})
		}
	}

	return list
}

// GenerateMarkdownReport generates a high-aesthetic markdown report of findings
func GenerateMarkdownReport(vulns []Vulnerability, target, outputDir string) string {
	reportPath := filepath.Join(outputDir, "WEB_SCAN_REPORT.md")
	_ = os.MkdirAll(outputDir, 0755)

	var b bytes.Buffer
	b.WriteString("# 🛡️ Mega-Analyzer — Web Vulnerability Scan Report\n\n")
	fmt.Fprintf(&b, "- **Target URL**: %s\n", target)
	fmt.Fprintf(&b, "- **Scan Time**: %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(&b, "- **Total Vulnerabilities**: %d\n\n", len(vulns))

	b.WriteString("## 📊 Summary Matrix\n\n")
	b.WriteString("| Severity | ID | Vulnerability | Parameter | Target URL |\n")
	b.WriteString("|---|---|---|---|---|\n")

	severityOrder := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
		SeverityInfo:     0,
	}

	// Sort findings by severity descending
	sort.Slice(vulns, func(i, j int) bool {
		return severityOrder[vulns[i].Severity] > severityOrder[vulns[j].Severity]
	})

	for _, v := range vulns {
		param := v.Parameter
		if param == "" {
			param = "N/A"
		}
		fmt.Fprintf(&b, "| **%s** | `%s` | %s | `%s` | %s |\n", v.Severity, v.ID, v.Name, param, v.URL)
	}

	b.WriteString("\n## 🔍 Gory Details\n\n")
	for i, v := range vulns {
		fmt.Fprintf(&b, "### %d. [%s] %s (`%s`)\n\n", i+1, v.Severity, v.Name, v.ID)
		fmt.Fprintf(&b, "**Description**:\n%s\n\n", v.Description)
		fmt.Fprintf(&b, "**Location/Target**:\nURL: %s\n", v.URL)
		if v.Parameter != "" {
			fmt.Fprintf(&b, "Parameter: `%s`\n", v.Parameter)
		}
		b.WriteString("\n")
		if v.Payload != "" {
			fmt.Fprintf(&b, "**Payload Used**:\n`%s`\n\n", v.Payload)
		}
		if v.Evidence != "" {
			fmt.Fprintf(&b, "**Evidence**:\n```text\n%s\n```\n\n", v.Evidence)
		}
		fmt.Fprintf(&b, "**Mitigation & Remediation Plan**:\n%s\n\n", v.Mitigation)
		b.WriteString("---\n\n")
	}

	_ = os.WriteFile(reportPath, b.Bytes(), 0644)
	return reportPath
}
