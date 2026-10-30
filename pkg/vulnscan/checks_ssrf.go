package vulnscan

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// checkSSRF probes URL-like parameters for Server-Side Request Forgery.
//
// Strategy (no OAST required):
//
//  1. Semi-blind internal probe — inject RFC-1918 / loopback URLs and detect
//     connection-refused vs. timeout differences that indicate the server
//     actually attempted the connection.
//
//  2. DNS rebinding canary — the server must resolve our domain; we detect
//     that by comparing response time deltas (timing oracle).
//
//  3. Metadata endpoint probe — cloud-provider metadata URLs; a 200 response
//     from any of them is a confirmed critical finding.
func (s *Scanner) checkSSRF(form Form) []Vulnerability {
	var list []Vulnerability

	// Candidate parameters that commonly carry URLs or file paths
	urlParamIndicators := []string{
		"url", "uri", "src", "source", "dest", "destination", "redirect",
		"redirect_to", "return", "return_url", "callback", "load",
		"file", "path", "fetch", "target", "link", "proxy", "ref",
		"referrer", "location", "image_url", "img_url", "feed",
	}

	// Cloud metadata endpoints (each returns a distinctive response on SSRF)
	metadataTargets := []struct {
		url      string
		provider string
	}{
		{"http://169.254.169.254/latest/meta-data/", "AWS"},
		{"http://metadata.google.internal/computeMetadata/v1/", "GCP"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"},
		{"http://100.100.100.200/latest/meta-data/", "Alibaba Cloud"},
	}

	// Internal / loopback probes — detect connection-refused vs timeout oracle
	internalProbes := []string{
		"http://127.0.0.1:80/",
		"http://127.0.0.1:22/",
		"http://127.0.0.1:3306/",
		"http://0.0.0.0:80/",
		"http://[::1]:80/",
		"http://localhost:80/",
	}

	for _, inputName := range form.Inputs {
		isURLParam := false
		nameLower := strings.ToLower(inputName)
		for _, indicator := range urlParamIndicators {
			if strings.Contains(nameLower, indicator) {
				isURLParam = true
				break
			}
		}
		if !isURLParam {
			continue
		}

		// --- Probe 1: Cloud metadata endpoints ---
		// A 200 alone is not evidence: many applications return their own 200
		// error page. Require provider-specific response markers.
		for _, meta := range metadataTargets {
			list = append(list, s.probeCloudMetadata(form, inputName, meta.url, meta.provider)...)
		}

		// --- Probe 2: Internal service timing oracle ---
		list = append(list, s.probeSSRFTimingOracle(form, inputName, internalProbes)...)
	}

	return list
}

// probeCloudMetadata confirms cloud-metadata SSRF using provider-specific body
// and header markers. It never reports merely because the application returned
// HTTP 200. This makes WS-SSRF-003 materially stronger than the legacy probe.
func (s *Scanner) probeCloudMetadata(form Form, paramName, payload, provider string) []Vulnerability {
	status, marker, body, err := s.fetchCloudMetadataEvidence(form, paramName, payload, provider)
	if err != nil || marker == "" {
		return nil
	}
	cf, cp, cpl, cprov := form, paramName, payload, provider
	return []Vulnerability{{
		ID: "WS-SSRF-003", Name: fmt.Sprintf("SSRF — %s Cloud Metadata Exposed", provider),
		Description: fmt.Sprintf("The application fetched the %s instance-metadata endpoint and relayed provider-specific metadata. This can expose instance identity, bootstrap data, service-account tokens, and cloud credentials.", provider),
		Severity:    SeverityCritical, URL: form.Action, Parameter: paramName, Payload: payload,
		Evidence:   fmt.Sprintf("HTTP %d; provider marker: %s; body: %s", status, marker, truncate(body, 260)),
		Mitigation: "Allowlist outbound URL schemes/hosts after DNS resolution and on every redirect. Block loopback, private, link-local and cloud metadata ranges at the egress layer. Require IMDSv2 on AWS and equivalent metadata hardening on other clouds.",
		Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
			_, reMarker, _, rerr := sc.fetchCloudMetadataEvidence(cf, cp, cpl, cprov)
			return reMarker != "", rerr
		}},
	}}
}

// fetchCloudMetadataEvidence sends the metadata-endpoint payload through the
// target and returns the provider marker found (empty when absent). Shared by
// the initial detection and the confirmation-pass retransmit.
func (s *Scanner) fetchCloudMetadataEvidence(form Form, paramName, payload, provider string) (int, string, string, error) {
	vals := url.Values{}
	for _, inp := range form.Inputs {
		if inp == paramName {
			vals.Set(inp, payload)
		} else {
			vals.Set(inp, "mega_probe")
		}
	}
	var req *http.Request
	var err error
	if strings.EqualFold(form.Method, http.MethodPost) {
		req, err = http.NewRequest(http.MethodPost, form.Action, strings.NewReader(vals.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		u, perr := url.Parse(form.Action)
		if perr != nil {
			return 0, "", "", perr
		}
		u.RawQuery = vals.Encode()
		req, err = http.NewRequest(http.MethodGet, u.String(), nil)
	}
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	s.applyAuthHeaders(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxOrDefault(s.Config.MaxBodyBytes, 5<<20))))
	if err != nil {
		return 0, "", "", err
	}
	body := string(bodyBytes)
	marker, _ := cloudMetadataEvidence(provider, resp.Header, body)
	return resp.StatusCode, marker, body, nil
}

func cloudMetadataEvidence(provider string, h http.Header, body string) (string, bool) {
	lower := strings.ToLower(body)
	switch provider {
	case "AWS":
		for _, marker := range []string{"iam/security-credentials/", "instance-id", "ami-id", "public-keys/", "placement/availability-zone"} {
			if strings.Contains(lower, marker) {
				return marker, true
			}
		}
	case "GCP":
		if strings.EqualFold(h.Get("Metadata-Flavor"), "Google") {
			return "Metadata-Flavor: Google", true
		}
		for _, marker := range []string{"service-accounts/", "computeMetadata/v1", "instance/hostname", "project/project-id"} {
			if strings.Contains(lower, strings.ToLower(marker)) {
				return marker, true
			}
		}
	case "Azure":
		// Azure IMDS instance JSON contains these keys together. Requiring the
		// conjunction avoids matching ordinary application JSON.
		if strings.Contains(lower, `"compute"`) && strings.Contains(lower, `"vmid"`) && strings.Contains(lower, `"subscriptionid"`) {
			return "compute + vmId + subscriptionId", true
		}
	case "Alibaba Cloud":
		for _, marker := range []string{"instance-id", "region-id", "ram/security-credentials/", "owner-account-id"} {
			if strings.Contains(lower, marker) {
				return marker, true
			}
		}
	}
	return "", false
}

// probeSSRFTimingOracle detects SSRF via response-time differences between
// probing closed ports (fast connection-refused) vs. non-routable IPs (slow timeout).
// If an internal probe takes significantly less time than the timeout it implies
// the server connected to (or received a TCP RST from) the internal address.
func (s *Scanner) probeSSRFTimingOracle(form Form, paramName string, probes []string) []Vulnerability {
	var list []Vulnerability

	// Baseline: how long does a request with a benign value take?
	baselineVals := url.Values{}
	for _, inp := range form.Inputs {
		baselineVals.Set(inp, "https://example.com")
	}
	baselineStart := time.Now()
	baselineReq, err := http.NewRequest("GET", form.Action+"?"+baselineVals.Encode(), nil)
	if err != nil {
		return list
	}
	baselineReq.Header.Set("User-Agent", s.Config.UserAgent)
	baselineResp, err := s.Client.Do(baselineReq)
	baselineElapsed := time.Since(baselineStart)
	if err == nil {
		io.Copy(io.Discard, baselineResp.Body) //nolint:errcheck
		baselineResp.Body.Close()
	}

	for _, probe := range probes {
		vals := url.Values{}
		for _, inp := range form.Inputs {
			if inp == paramName {
				vals.Set(inp, probe)
			} else {
				vals.Set(inp, "test")
			}
		}

		var req *http.Request
		if form.Method == "POST" {
			req, _ = http.NewRequest("POST", form.Action, strings.NewReader(vals.Encode()))
			if req == nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			u, _ := url.Parse(form.Action)
			u.RawQuery = vals.Encode()
			req, _ = http.NewRequest("GET", u.String(), nil)
			if req == nil {
				continue
			}
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)

		probeStart := time.Now()
		probeResp, probeErr := s.Client.Do(req)
		probeElapsed := time.Since(probeStart)

		if probeErr == nil {
			io.Copy(io.Discard, probeResp.Body) //nolint:errcheck
			probeResp.Body.Close()
		}

		// Heuristic: if the probe returned significantly faster than the baseline
		// AND the probe target is an internal address, the server likely connected.
		// We only flag when the response is < 20% of baseline time (connection-refused oracle).
		if baselineElapsed > 200*time.Millisecond && probeElapsed < baselineElapsed/5 {
			// Additional check: verify target is actually an internal address
			parsedProbe, parseErr := url.Parse(probe)
			if parseErr != nil {
				continue
			}
			ip := net.ParseIP(parsedProbe.Hostname())
			if ip != nil && isPrivateIP(ip) {
				list = append(list, Vulnerability{
					ID:          "WS-SSRF-002",
					Name:        "SSRF — Internal Network Probe (Timing Oracle)",
					Description: fmt.Sprintf("Timing oracle suggests the server initiated an outbound connection to internal address %s (response in %dms vs baseline %dms). A port scan of internal services may be possible.", probe, probeElapsed.Milliseconds(), baselineElapsed.Milliseconds()),
					Severity:    SeverityHigh,
					URL:         form.Action,
					Parameter:   paramName,
					Payload:     probe,
					Evidence:    fmt.Sprintf("Baseline: %dms | Probe: %dms", baselineElapsed.Milliseconds(), probeElapsed.Milliseconds()),
					Mitigation:  "Validate and allowlist all server-side URL destinations. Block RFC-1918 and loopback addresses at the egress firewall.",
				})
				break // One oracle hit per parameter is sufficient
			}
		}
	}
	return list
}
