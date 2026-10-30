package vulnscan

// Web Cache Deception (CWE-525). Appends a static-looking path suffix
// (e.g. /nonexistent.css) to an authenticated endpoint. If the origin still
// serves the dynamic (authenticated) content AND a caching layer treats the
// response as a cacheable static asset, private data can be cached and later
// served to anonymous users.

import (
	"fmt"
	"net/http"
	"strings"
)

// cacheDeceptionPath builds a deception variant of a base path by appending a
// static-looking segment. Exposed (lowercase-unexported) for unit testing.
func cacheDeceptionPath(basePath, staticSeg string) string {
	if basePath == "" {
		basePath = "/"
	}
	if strings.HasSuffix(basePath, "/") {
		return basePath + staticSeg
	}
	return basePath + "/" + staticSeg
}

func looksCacheHit(h http.Header) (string, bool) {
	candidates := map[string][]string{
		"X-Cache":         {"hit"},
		"Cf-Cache-Status": {"hit"},
		"X-Cache-Status":  {"hit"},
		"X-Drupal-Cache":  {"hit"},
		"Age":             {},
	}
	for k, wants := range candidates {
		v := h.Get(k)
		if v == "" {
			continue
		}
		if len(wants) == 0 {
			return k + ": " + v, true // Age header present => served from cache
		}
		lv := strings.ToLower(v)
		for _, w := range wants {
			if strings.Contains(lv, w) {
				return k + ": " + v, true
			}
		}
	}
	return "", false
}

func cacheableContentType(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "public") && !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") {
		return true
	}
	return false
}

// checkCacheDeception probes the target for web cache deception.
func (s *Scanner) checkCacheDeception() []Vulnerability {
	var list []Vulnerability
	if s.BaseURL == nil || s.Client == nil {
		return list
	}
	// Deception is only interesting for authenticated content.
	if s.Config.AuthCookie == "" && s.Config.AuthBearer == "" {
		return list
	}

	basePath := s.BaseURL.Path
	statics := []string{"nonexistent-mega.css", "nonexistent-mega.js", "nonexistent-mega.jpg"}

	for _, seg := range statics {
		u := *s.BaseURL
		u.Path = cacheDeceptionPath(basePath, seg)

		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}
		s.applyAuthHeaders(req)
		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}
		body, _ := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
		resp.Body.Close()

		// The origin served authenticated 200 content for a static-looking URL.
		if resp.StatusCode != 200 {
			continue
		}
		hit, isHit := looksCacheHit(resp.Header)
		cacheable := cacheableContentType(resp.Header)
		if !isHit && !cacheable {
			continue
		}
		// Reduce FP: require the body to look dynamic (not a tiny 404 page).
		if len(body) < 256 {
			continue
		}
		sev := SeverityMedium
		if isHit {
			sev = SeverityHigh
		}
		evidence := "authenticated 200 served for static-suffixed path"
		if hit != "" {
			evidence += "; cache indicator " + hit
		} else {
			evidence += "; response marked publicly cacheable"
		}
		list = append(list, Vulnerability{
			ID:          "WS-CACHE-002",
			Name:        "Web Cache Deception",
			Description: "An authenticated endpoint returned dynamic content for a static-looking URL that a caching layer may store, allowing private responses to be cached and served to other users.",
			Severity:    sev,
			URL:         u.String(),
			Payload:     seg,
			Evidence:    fmt.Sprintf("%s (%d bytes)", evidence, len(body)),
			Mitigation:  "Cache by full path and content type; never cache responses to authenticated requests; ensure the origin returns 404 for non-existent static paths instead of the dynamic page.",
		})
		break
	}

	return list
}
