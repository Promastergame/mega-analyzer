package playstore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Metadata holds scraped Play Store metadata.
type Metadata struct {
	PackageName   string  `json:"package_name"`
	Name          string  `json:"name"`
	Developer     string  `json:"developer"`
	Category      string  `json:"category"`
	Description   string  `json:"description"`
	Rating        float64 `json:"rating"`
	RatingCount   string  `json:"rating_count"`
	Installs      string  `json:"installs"`
	Version       string  `json:"version"`
	Updated       string  `json:"updated"`
	PrivacyPolicy string  `json:"privacy_policy"`
	URL           string  `json:"url"`
	Found         bool    `json:"found"`
	Error         string  `json:"error,omitempty"`
}

// FetchMetadata scrapes Play Store for a given package name.
func FetchMetadata(packageName string) (*Metadata, error) {
	return FetchMetadataWithContext(context.Background(), packageName)
}

// FetchMetadataWithContext is FetchMetadata with caller cancellation: the
// 10s client timeout still bounds a hung server, the context lets the
// runner abort the wait early.
func FetchMetadataWithContext(ctx context.Context, packageName string) (*Metadata, error) {
	return fetchMetadata(ctx, packageName, "https://play.google.com")
}

// maxBodyBytes caps a store page: pages are ~1-2 MiB, anything larger is
// either a MitM surprise or a changed format — not something to buffer whole.
const maxBodyBytes = 8 << 20

// packageNameRe is the Android package grammar (segments start with a
// letter, at least one dot). Anything else — including "&", "?", "%", or
// control bytes — is rejected before it reaches the URL: the old code let
// http.NewRequest be the only validator, so "a&b=c" silently rewrote the
// query while only control bytes errored out.
var packageNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func fetchMetadata(ctx context.Context, packageName, baseURL string) (*Metadata, error) {
	if packageName == "" {
		return &Metadata{Error: "empty package name"}, nil
	}
	if len(packageName) > 256 || !packageNameRe.MatchString(packageName) {
		return &Metadata{PackageName: packageName, Error: "invalid package name"}, nil
	}
	url := fmt.Sprintf("%s/store/apps/details?id=%s&hl=en", strings.TrimSuffix(baseURL, "/"), packageName)
	client := &http.Client{Timeout: 10 * time.Second}

	var resp *http.Response
	var err error
	// One retry on transient statuses; 404 and other finals return at once.
	for attempt := 0; ; attempt++ {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err = client.Do(req)
		if err != nil {
			return &Metadata{PackageName: packageName, Error: err.Error()}, nil
		}
		if !retryableStatus(resp.StatusCode) || attempt >= 1 {
			break
		}
		resp.Body.Close()
		select {
		case <-ctx.Done():
			return &Metadata{PackageName: packageName, Error: ctx.Err().Error()}, nil
		case <-time.After(time.Second):
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &Metadata{PackageName: packageName, Found: false, Error: "not found on Play Store"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return &Metadata{PackageName: packageName, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return &Metadata{PackageName: packageName, Error: err.Error()}, nil
	}
	if len(body) > maxBodyBytes {
		return &Metadata{PackageName: packageName, Error: "response too large"}, nil
	}
	return parseBody(packageName, string(body)), nil
}

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

var (
	// (?s): the JSON-LD block is usually one line, but pretty-printed
	// pages put newlines inside it — without (?s) the block is missed.
	jsonLdRe      = regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)
	ratingRe      = regexp.MustCompile(`"ratingValue":"([0-9.]+)"`)
	ratingCountRe = regexp.MustCompile(`"ratingCount":"([0-9,]+)"`)
	// Best-effort downloads token: a quoted digit run ending in "+"
	// ("1,000,000+"). Dots are excluded so versions ("1.2.3+") can't match.
	installsRe = regexp.MustCompile(`"([0-9][0-9,]*\+)"`)
	versionRe  = regexp.MustCompile(`Current Version</div>[^<]*<span[^>]*class="[^"]*">([^<]+)</span>`)
	updatedRe  = regexp.MustCompile(`Updated on</div>[^<]*<span[^>]*class="[^"]*">([^<]+)</span>`)
	privacyRe  = regexp.MustCompile(`privacy_policy[^"]*"[^>]*href="([^"]+)"`)
)

func parseBody(pkg, body string) *Metadata {
	m := &Metadata{PackageName: pkg, Found: true}

	// JSON-LD block usually contains name, description, developer, etc.
	matches := jsonLdRe.FindStringSubmatch(body)
	if len(matches) > 1 {
		var ld map[string]interface{}
		if err := json.Unmarshal([]byte(matches[1]), &ld); err == nil {
			if v, ok := ld["name"].(string); ok {
				m.Name = v
			}
			if v, ok := ld["description"].(string); ok {
				m.Description = cleanText(v)
			}
			if v, ok := ld["author"].(map[string]interface{}); ok {
				if n, ok := v["name"].(string); ok {
					m.Developer = n
				}
			}
			if v, ok := ld["aggregateRating"].(map[string]interface{}); ok {
				if r, ok := v["ratingValue"].(string); ok {
					fmt.Sscanf(r, "%f", &m.Rating)
				}
				if c, ok := v["ratingCount"].(string); ok {
					m.RatingCount = c
				}
			}
			if v, ok := ld["applicationCategory"].(string); ok {
				m.Category = v
			}
		}
	}

	if m.Rating == 0 {
		if match := ratingRe.FindStringSubmatch(body); len(match) > 1 {
			fmt.Sscanf(match[1], "%f", &m.Rating)
		}
	}
	if m.RatingCount == "" {
		if match := ratingCountRe.FindStringSubmatch(body); len(match) > 1 {
			m.RatingCount = match[1]
		}
	}

	if match := versionRe.FindStringSubmatch(body); len(match) > 1 {
		m.Version = strings.TrimSpace(match[1])
	}
	if match := updatedRe.FindStringSubmatch(body); len(match) > 1 {
		m.Updated = strings.TrimSpace(match[1])
	}
	if match := installsRe.FindStringSubmatch(body); len(match) > 1 {
		m.Installs = match[1]
	}
	if match := privacyRe.FindStringSubmatch(body); len(match) > 1 {
		m.PrivacyPolicy = match[1]
	}

	m.URL = fmt.Sprintf("https://play.google.com/store/apps/details?id=%s", pkg)
	return m
}

func cleanText(s string) string {
	s = strings.ReplaceAll(s, "\u00a0", " ")
	s = strings.ReplaceAll(s, "\u200b", "")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// Report is the JSON/Markdown serializable result.
type Report struct {
	GeneratedAt string    `json:"generated_at"`
	Metadata    *Metadata `json:"metadata"`
	Score       int       `json:"score"`
	Verdict     string    `json:"verdict"`
}

// Analyze wraps FetchMetadata into a report.
func Analyze(packageName string) *Report {
	meta, _ := FetchMetadata(packageName)
	verdict := "unknown"
	if meta != nil {
		if meta.Found {
			verdict = "published"
		} else if meta.Error == "not found on Play Store" {
			verdict = "sideloaded"
		}
	}
	return &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Metadata:    meta,
		Verdict:     verdict,
	}
}
