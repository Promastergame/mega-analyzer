package vulnscan

import (
	"fmt"
	"regexp"
	"strings"
)

// testCSRF checks if state-changing forms (POST/PUT/DELETE) have CSRF protection.
// It relies on static analysis of the form fields extracted during crawling.
func (s *Scanner) testCSRF(form Form, cookies []string) []Vulnerability {
	var list []Vulnerability

	// CSRF is primarily a concern for state-changing requests
	method := strings.ToUpper(form.Method)
	if method == "GET" || method == "OPTIONS" || method == "HEAD" {
		return list
	}

	hasCSRFToken := false
	csrfParamRe := regexp.MustCompile(`(?i)(csrf|xsrf|authenticity_token|_token|token)`)

	// 1. Check if any input looks like a CSRF token
	for _, inputName := range form.Inputs {
		if csrfParamRe.MatchString(inputName) {
			hasCSRFToken = true
			break
		}
	}

	// 2. Check if SameSite=Strict/Lax protects the session
	hasSameSiteProtection := false
	for _, cookieStr := range cookies {
		lowerCookie := strings.ToLower(cookieStr)
		if strings.Contains(lowerCookie, "samesite=strict") || strings.Contains(lowerCookie, "samesite=lax") {
			if isSessionCookie(cookieStr) {
				hasSameSiteProtection = true
				break
			}
		}
	}

	if !hasCSRFToken && !hasSameSiteProtection {
		list = append(list, Vulnerability{
			ID:          "WS-CSRF-001",
			Name:        "Missing Cross-Site Request Forgery (CSRF) Protection",
			Description: fmt.Sprintf("The %s form to %s does not appear to contain an anti-CSRF token (e.g., a hidden field like 'csrf_token'). Furthermore, session cookies do not use SameSite=Strict/Lax.", method, form.Action),
			Severity:    SeverityMedium,
			URL:         form.Action,
			Evidence:    fmt.Sprintf("Method: %s. Form inputs analyzed: %v. No anti-CSRF parameter found.", method, form.Inputs),
			Mitigation:  "Implement synchronizer token pattern (anti-CSRF tokens) for all state-changing requests, and configure session cookies with SameSite=Lax or SameSite=Strict.",
		})
	}

	return list
}
