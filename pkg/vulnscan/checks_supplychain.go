package vulnscan

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	scriptTagRE = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	scriptSrcRE = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']([^"']+)["']`)
	integrityRE = regexp.MustCompile(`(?i)\bintegrity\s*=\s*["'][^"']+["']`)
	cardFieldRE = regexp.MustCompile(`(?i)(card(number)?|credit.?card|cvv|cvc|expiry|expiration|billing)`)
	exfilSinkRE = regexp.MustCompile(`(?i)(fetch\s*\(|XMLHttpRequest|sendBeacon\s*\(|new\s+Image\s*\(|\.src\s*=)`)
	dynamicJSRE = regexp.MustCompile(`(?i)(eval\s*\(\s*atob|document\.write\s*\(.*<script|createElement\s*\(\s*["']script|localStorage|sessionStorage)`)
)

// checkJSSupplyChain performs passive Magecart/third-party script analysis.
// A missing SRI attribute alone is only reported when the script is genuinely
// cross-origin. The high-severity Magecart signal requires a correlation of
// payment-data terms, an exfiltration sink, and dynamic/obfuscated JavaScript.
func (s *Scanner) checkJSSupplyChain(body, pageURL string) []Vulnerability {
	var out []Vulnerability
	page, _ := url.Parse(pageURL)
	if page == nil {
		// Fallback: treat as an opaque local URL so cross-origin checks are skipped
		page = &url.URL{}
	}
	seenOrigin := map[string]bool{}

	for _, match := range scriptTagRE.FindAllStringSubmatch(body, -1) {
		attrs, inline := match[1], match[2]
		if src := scriptSrcRE.FindStringSubmatch(attrs); len(src) == 2 {
			resolved, err := page.Parse(strings.TrimSpace(src[1]))
			if err == nil && resolved.Hostname() != "" && page.Hostname() != "" &&
				!strings.EqualFold(resolved.Hostname(), page.Hostname()) && !integrityRE.MatchString(attrs) {
				origin := resolved.Scheme + "://" + resolved.Host
				if !seenOrigin[origin] {
					seenOrigin[origin] = true
					out = append(out, Vulnerability{
						ID:          "WS-SUPPLY-001",
						Name:        "Third-Party JavaScript Without Subresource Integrity",
						Description: "A cross-origin script executes with first-party privileges but has no integrity pin. Compromise of the CDN/vendor account can inject Magecart-style payment skimmers or session stealers.",
						Severity:    SeverityMedium,
						URL:         pageURL,
						Parameter:   "script[src]",
						Evidence:    fmt.Sprintf("Cross-origin script without integrity=sha256/384/512: %s", truncate(resolved.String(), 240)),
						Mitigation:  "Self-host security-critical JavaScript or pin immutable third-party assets with Subresource Integrity and crossorigin=anonymous. Enforce a nonce/hash-based CSP and continuously inventory script origins.",
					})
				}
			}
		}

		if inline != "" {
			if f := magecartPatternFinding(inline, pageURL); f != nil {
				out = append(out, *f)
			}
		}
	}
	return out
}

// magecartPatternFinding reports the high-confidence skimmer correlation when a
// JavaScript source block combines payment-card field access, a network
// exfiltration sink, and dynamic/obfuscated execution. It is shared between
// inline <script> analysis and standalone .js/.mjs file analysis.
func magecartPatternFinding(jsSource, pageURL string) *Vulnerability {
	if jsSource == "" {
		return nil
	}
	if cardFieldRE.MatchString(jsSource) && exfilSinkRE.MatchString(jsSource) && dynamicJSRE.MatchString(jsSource) {
		return &Vulnerability{
			ID:          "WS-SUPPLY-001",
			Name:        "Magecart-Style Payment Skimmer Pattern",
			Description: "Inline JavaScript correlates payment-card field access with a network exfiltration sink and dynamic/obfuscated script behavior. This is a high-confidence client-side skimmer pattern requiring immediate incident response.",
			Severity:    SeverityHigh,
			URL:         pageURL,
			Evidence:    truncate(strings.TrimSpace(jsSource), 320),
			Mitigation:  "Quarantine the page, preserve the script for incident response, rotate affected credentials, verify deployment/CDN integrity, and restrict payment pages with strict CSP, SRI, Trusted Types, and script-change monitoring.",
		}
	}
	return nil
}
