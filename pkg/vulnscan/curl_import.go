package vulnscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CurlRequest represents a parsed curl command
type CurlRequest struct {
	Method   string
	URL      string
	Headers  map[string]string
	Body     string
	Insecure bool
}

// ParseCurlCommand parses a curl command string into a CurlRequest.
// Supports: -H/--header, -X/--request, -d/--data/--data-raw/--data-binary,
// -b/--cookie, -u/--user, -k/--insecure, --compressed (ignored).
func ParseCurlCommand(cmd string) (*CurlRequest, error) {
	tokens, err := tokenizeCurl(cmd)
	if err != nil {
		return nil, err
	}

	req := &CurlRequest{
		Method:  "GET",
		Headers: make(map[string]string),
	}

	i := 0
	for i < len(tokens) {
		tok := tokens[i]

		switch {
		case tok == "curl":
			// skip

		case tok == "-X" || tok == "--request":
			i++
			if i < len(tokens) {
				req.Method = strings.ToUpper(tokens[i])
			}

		case tok == "-H" || tok == "--header":
			i++
			if i < len(tokens) {
				parts := strings.SplitN(tokens[i], ":", 2)
				if len(parts) == 2 {
					req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}

		case tok == "-d" || tok == "--data" || tok == "--data-raw" || tok == "--data-binary" || tok == "--data-urlencode":
			i++
			if i < len(tokens) {
				req.Body = tokens[i]
				if req.Method == "GET" {
					req.Method = "POST"
				}
			}

		case tok == "-b" || tok == "--cookie":
			i++
			if i < len(tokens) {
				existing := req.Headers["Cookie"]
				if existing != "" {
					req.Headers["Cookie"] = existing + "; " + tokens[i]
				} else {
					req.Headers["Cookie"] = tokens[i]
				}
			}

		case tok == "-u" || tok == "--user":
			i++
			if i < len(tokens) {
				req.Headers["Authorization"] = "Basic " + tokens[i]
			}

		case tok == "-k" || tok == "--insecure":
			req.Insecure = true

		case tok == "--compressed":
			// ignore — we handle decompression automatically

		case tok == "-A" || tok == "--user-agent":
			i++
			if i < len(tokens) {
				req.Headers["User-Agent"] = tokens[i]
			}

		case tok == "--url" || (!strings.HasPrefix(tok, "-") && req.URL == ""):
			// positional URL argument
			if tok != "--url" {
				req.URL = tok
			} else {
				i++
				if i < len(tokens) {
					req.URL = tokens[i]
				}
			}

		case tok == "-e" || tok == "--referer" || tok == "--referrer":
			i++
			if i < len(tokens) {
				req.Headers["Referer"] = tokens[i]
			}

		case tok == "-s" || tok == "--silent" ||
			tok == "-v" || tok == "--verbose" ||
			tok == "-L" || tok == "--location" ||
			tok == "-I" || tok == "--head" ||
			tok == "-i" || tok == "--include" ||
			tok == "-S" || tok == "--show-error" ||
			tok == "--http1.1" || tok == "--http2" || tok == "--http3":
			// cosmetic / redirect following flags — skip silently

		default:
			// Unknown flag — skip
		}

		i++
	}

	if req.URL == "" {
		return nil, fmt.Errorf("no URL found in curl command")
	}

	// Normalise URL
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		req.URL = "https://" + req.URL
	}

	return req, nil
}

// ToHTTPRequest converts a CurlRequest to a standard *http.Request
func (cr *CurlRequest) ToHTTPRequest() (*http.Request, error) {
	var bodyReader io.Reader
	if cr.Body != "" {
		bodyReader = strings.NewReader(cr.Body)
	}

	req, err := http.NewRequest(cr.Method, cr.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	for k, v := range cr.Headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// BuildHTTPClient creates an http.Client respecting the CurlRequest settings (e.g. insecure TLS)
func (cr *CurlRequest) BuildHTTPClient(base *http.Client) *http.Client {
	if !cr.Insecure {
		return base
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	c := *base
	c.Transport = transport
	return &c
}

// ParseRawHTTPRequest parses a raw HTTP request (Burp Suite style) into an *http.Request.
// The host is used to build the full URL when the request-line has a relative path.
// Example input:
//
//	POST /login HTTP/1.1
//	Host: example.com
//	Content-Type: application/x-www-form-urlencoded
//
//	username=admin&password=pass
func ParseRawHTTPRequest(raw string, defaultScheme string) (*http.Request, error) {
	if defaultScheme == "" {
		defaultScheme = "https"
	}

	reader := bufio.NewReader(strings.NewReader(raw))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw HTTP request: %w", err)
	}

	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host == "" {
		return nil, fmt.Errorf("raw HTTP request is missing a Host header")
	}

	scheme := defaultScheme
	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reconstructed URL %s: %w", fullURL, err)
	}
	req.URL = parsedURL
	req.RequestURI = "" // must be cleared for client use

	return req, nil
}

// ExportVulnAsCurl generates a curl command that reproduces the finding.
// It takes the original request context and the specific payload used.
func ExportVulnAsCurl(v Vulnerability, method string, headers map[string]string, body string) string {
	var sb strings.Builder

	sb.WriteString("curl")

	if method != "" && method != "GET" {
		sb.WriteString(fmt.Sprintf(" -X %s", method))
	}

	targetURL := v.URL
	if v.Parameter != "" && v.Payload != "" && (method == "GET" || method == "") {
		// Inject payload into URL query string for GET
		u, err := url.Parse(targetURL)
		if err == nil {
			q := u.Query()
			q.Set(v.Parameter, v.Payload)
			u.RawQuery = q.Encode()
			targetURL = u.String()
		}
	}

	sb.WriteString(fmt.Sprintf(" '%s'", targetURL))

	for k, val := range headers {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "transfer-encoding" {
			continue
		}
		sb.WriteString(fmt.Sprintf(" \\\n  -H '%s: %s'", k, val))
	}

	if body != "" && v.Parameter != "" && v.Payload != "" && method != "GET" {
		// Inject payload into body
		vals, err := url.ParseQuery(body)
		if err == nil {
			vals.Set(v.Parameter, v.Payload)
			sb.WriteString(fmt.Sprintf(" \\\n  --data '%s'", vals.Encode()))
		} else {
			sb.WriteString(fmt.Sprintf(" \\\n  --data '%s'", body))
		}
	} else if body != "" {
		sb.WriteString(fmt.Sprintf(" \\\n  --data '%s'", body))
	}

	sb.WriteString(" \\\n  -k") // insecure for pentest convenience

	return sb.String()
}

// tokenizeCurl splits a curl command string into tokens, respecting
// single-quoted, double-quoted, and backslash-escaped segments.
func tokenizeCurl(cmd string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	runes := []rune(strings.TrimSpace(cmd))
	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			} else {
				current.WriteRune(ch)
			}

		case inDouble:
			if ch == '"' {
				inDouble = false
			} else if ch == '\\' && i+1 < len(runes) {
				i++
				current.WriteRune(runes[i])
			} else {
				current.WriteRune(ch)
			}

		case ch == '\'':
			inSingle = true

		case ch == '"':
			inDouble = true

		case ch == '\\' && i+1 < len(runes):
			next := runes[i+1]
			if next == '\n' || next == '\r' {
				// line continuation — skip
				i++
			} else {
				i++
				current.WriteRune(runes[i])
			}

		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}

		default:
			current.WriteRune(ch)
		}
	}

	if inSingle {
		return nil, fmt.Errorf("unterminated single quote in curl command")
	}
	if inDouble {
		return nil, fmt.Errorf("unterminated double quote in curl command")
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}
