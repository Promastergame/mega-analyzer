package vulnscan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// Patterns for extracting API endpoints and routes from JS bundles and extensionless blobs
	jsAPIEndpointRE  = regexp.MustCompile(`(?i)(?:https?://[a-zA-Z0-9\-\.]+(?:\:[0-9]+)?|/[a-zA-Z0-9_\-/]+)/(?:api|v[0-9]+|graphql|rest|auth|login|token|user|track|playlist|playback)/[a-zA-Z0-9_\-/?&=%]*`)
	jsRelativePathRE = regexp.MustCompile(`(?i)["'](/(?:api|v[0-9]+|graphql|ws|rest|service|track|album|artist|search|collection)/[a-zA-Z0-9_\-/?&=%]*)["']`)
)

// AssetInventory tracks files discovered and analyzed in a web directory dump
type AssetInventory struct {
	TotalFiles          int      `json:"total_files"`
	HTMLFiles           int      `json:"html_files"`
	JSFiles             int      `json:"js_files"`
	CSSFiles            int      `json:"css_files"`
	Extensionless       int      `json:"extensionless_files"`
	OtherFiles          int      `json:"other_files"`
	DiscoveredEndpoints []string `json:"discovered_endpoints"`
}

// ScanHTMLDirectory scans an entire directory of saved webpage files (HTML, JS, CSS, extensionless blobs,
// including browser-downloaded suffixes like .js.загружено or .js.downloaded).
func (s *Scanner) ScanHTMLDirectory(dirPath string) ([]Vulnerability, error) {
	var allVulns []Vulnerability
	seenFindings := make(map[string]bool)
	seenEndpoints := make(map[string]bool)
	inventory := AssetInventory{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		body := string(data)
		sourceURL := "file://" + filepath.ToSlash(path)

		// Classify file type
		fileType := classifyFileType(path, body)
		switch fileType {
		case "html":
			inventory.HTMLFiles++
		case "js":
			inventory.JSFiles++
		case "css":
			inventory.CSSFiles++
		case "extensionless":
			inventory.Extensionless++
		default:
			inventory.OtherFiles++
		}
		inventory.TotalFiles++

		// Extract API endpoints / routes from JS / HTML content
		endpoints := extractEndpoints(body)
		for _, ep := range endpoints {
			if !seenEndpoints[ep] {
				seenEndpoints[ep] = true
				inventory.DiscoveredEndpoints = append(inventory.DiscoveredEndpoints, ep)
			}
		}

		vulns := s.ScanFileContent(path, body, sourceURL)
		for _, v := range vulns {
			key := fmt.Sprintf("%s|%s|%s|%s", v.ID, v.URL, v.Parameter, v.Evidence)
			if !seenFindings[key] {
				seenFindings[key] = true
				allVulns = append(allVulns, v)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Add an INFO-level inventory finding if endpoints or extensionless assets were found
	if len(inventory.DiscoveredEndpoints) > 0 || inventory.Extensionless > 0 {
		evidence := fmt.Sprintf("Scanned %d files (%d HTML, %d JS, %d CSS, %d extensionless blobs). Discovered %d unique API endpoints/routes.",
			inventory.TotalFiles, inventory.HTMLFiles, inventory.JSFiles, inventory.CSSFiles, inventory.Extensionless, len(inventory.DiscoveredEndpoints))

		previewEndpoints := inventory.DiscoveredEndpoints
		if len(previewEndpoints) > 25 {
			previewEndpoints = previewEndpoints[:25]
		}
		if len(previewEndpoints) > 0 {
			evidence += "\n\nDiscovered Endpoints Preview:\n  - " + strings.Join(previewEndpoints, "\n  - ")
		}

		allVulns = append(allVulns, Vulnerability{
			ID:          "WS-INV-001",
			Name:        "Web Directory & Asset Endpoint Inventory",
			Description: "Passive analysis of saved webpage directory revealed internal assets, extensionless blobs, and referenced API endpoints / GraphQL routes.",
			Severity:    SeverityInfo,
			URL:         "file://" + filepath.ToSlash(dirPath),
			Evidence:    evidence,
			Mitigation:  "Review exposed API routes and ensure sensitive admin/backend endpoints are properly protected with authentication and authorization controls.",
		})
	}

	return allVulns, nil
}

// classifyFileType determines whether a file is html, js, css, extensionless blob, or other,
// using both path/extension and magic bytes / content heuristics.
func classifyFileType(filePath, body string) string {
	lowerPath := strings.ToLower(filePath)
	cleanedPath := lowerPath
	for _, suffix := range []string{".загружено", ".downloaded", ".part", ".crdownload", ".orig"} {
		cleanedPath = strings.TrimSuffix(cleanedPath, suffix)
	}

	if strings.HasSuffix(cleanedPath, ".html") || strings.HasSuffix(cleanedPath, ".htm") || strings.HasSuffix(cleanedPath, ".shtml") {
		return "html"
	}
	if strings.HasSuffix(cleanedPath, ".js") || strings.HasSuffix(cleanedPath, ".mjs") || strings.HasSuffix(cleanedPath, ".ts") {
		return "js"
	}
	if strings.HasSuffix(cleanedPath, ".css") {
		return "css"
	}
	if strings.HasSuffix(cleanedPath, ".json") {
		return "json"
	}

	// Check if filename has no extension (e.g. ab6761610000101f...)
	base := filepath.Base(cleanedPath)
	hasExtension := strings.Contains(base, ".")

	if !hasExtension || strings.HasPrefix(base, "ab67") || len(base) > 30 {
		// Heuristics based on content
		trimmed := strings.TrimSpace(body)
		if strings.HasPrefix(trimmed, "<!DOCTYPE") || strings.HasPrefix(trimmed, "<html") {
			return "html"
		}
		if strings.Contains(trimmed, "webpackChunk") || strings.Contains(trimmed, "function(") || strings.Contains(trimmed, "use strict") || strings.Contains(trimmed, "exports") {
			return "js"
		}
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") && (strings.Contains(trimmed, "\"") || strings.Contains(trimmed, "'")) {
			return "json"
		}
		if strings.Contains(trimmed, "body {") || strings.Contains(trimmed, "margin:") || strings.Contains(trimmed, "padding:") {
			return "css"
		}
		return "extensionless"
	}

	return "other"
}

// extractEndpoints scans text body for API routes and endpoints
func extractEndpoints(body string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	// Absolute URLs matching API patterns
	for _, m := range jsAPIEndpointRE.FindAllString(body, -1) {
		clean := strings.Trim(m, "\"'`()")
		if !seen[clean] && len(clean) < 150 {
			seen[clean] = true
			endpoints = append(endpoints, clean)
		}
	}

	// Relative path API endpoints
	for _, m := range jsRelativePathRE.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			clean := strings.Trim(m[1], "\"'`()")
			if !seen[clean] && len(clean) < 100 {
				seen[clean] = true
				endpoints = append(endpoints, clean)
			}
		}
	}

	return endpoints
}

// ScanFileContent classifies a file based on its name/extension (handling browser-saved suffixes)
// and runs appropriate passive analysis checks.
func (s *Scanner) ScanFileContent(filePath, body, sourceURL string) []Vulnerability {
	vulns := make([]Vulnerability, 0)
	fileType := classifyFileType(filePath, body)

	// Always run secret detection and dynamic passive rules on any text file
	vulns = append(vulns, s.detectSecrets(body, sourceURL)...)
	vulns = append(vulns, s.RunDynamicPassiveRules(body, sourceURL)...)

	switch fileType {
	case "html", "extensionless":
		vulns = append(vulns, s.checkPassiveWebExtras(body, sourceURL)...)
		vulns = append(vulns, s.checkJSSupplyChain(body, sourceURL)...)
	case "js":
		// Standalone script files carry no <script> wrapper, so run the
		// skimmer correlation directly on the raw source in addition to the
		// tag-based analysis (which still catches embedded HTML snippets).
		vulns = append(vulns, s.checkPassiveWebExtras(body, sourceURL)...)
		vulns = append(vulns, s.checkJSSupplyChain(body, sourceURL)...)
		if f := magecartPatternFinding(body, sourceURL); f != nil {
			vulns = append(vulns, *f)
		}
	case "css":
		// CSS files can contain imported URLs or background assets
	case "json":
		// JSON files might contain config secrets or api endpoints
	default:
		vulns = append(vulns, s.checkPassiveWebExtras(body, sourceURL)...)
	}

	return vulns
}
