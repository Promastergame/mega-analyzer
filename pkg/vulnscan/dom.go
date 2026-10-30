package vulnscan

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/cdp"
	"mega-analyzer/pkg/internal/cdp/network"
)

// decodeCDPPostBodies returns the decoded request bodies carried by a CDP
// Network.requestWillBeSent event. Entry bytes are base64 by protocol;
// PostData, when present, is already plain text. complete is false when an
// entry could not be decoded, so callers can mark the capture incomplete
// instead of silently testing a truncated parameter set.
func decodeCDPPostBodies(req *network.Request) (bodies [][]byte, complete bool) {
	complete = true
	if req == nil {
		return nil, true
	}
	if req.PostData != "" {
		bodies = append(bodies, []byte(req.PostData))
	}
	for _, entry := range req.PostDataEntries {
		if entry == nil || entry.Bytes == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(entry.Bytes)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(entry.Bytes)
		}
		if err != nil {
			complete = false
			continue
		}
		bodies = append(bodies, decoded)
	}
	return bodies, complete
}

// resolveSafeDOMHostRule validates targetURL against SSRF (internal/private
// IPs) and, for hostnames, returns a Chrome --host-resolver-rules value that
// pins the hostname to the IP we just validated. chromedp's headless Chrome
// does its own independent DNS resolution — without this pin, a hostname
// that resolves to a public IP at validation time could rebind to an
// internal address (e.g. 169.254.169.254, 127.0.0.1) by the time Chrome
// actually connects, bypassing the check entirely (TOCTOU).
func resolveSafeDOMHostRule(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("bad url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported scheme: %s", scheme)
	}
	host := u.Hostname()
	clean := strings.TrimSuffix(strings.ToLower(host), ".")
	if clean == "" {
		return "", fmt.Errorf("empty host")
	}
	if clean == "localhost" || clean == "localhost.localdomain" ||
		clean == "::1" || clean == "::" || clean == "0.0.0.0" {
		return "", fmt.Errorf("blocked host: %s", clean)
	}

	if ip := net.ParseIP(clean); ip != nil {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("private IP: %s", ip)
		}
		return "", nil // literal IP target: nothing to pin
	}

	addrs, err := net.LookupHost(clean)
	if err != nil {
		return "", fmt.Errorf("dns resolve: %w", err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && !isPrivateIP(ip) {
			return fmt.Sprintf("MAP %s %s", host, ip.String()), nil
		}
	}
	return "", fmt.Errorf("no safe IP resolved for %s", clean)
}

// ExtractDOMForms uses a headless browser to render SPAs and extract dynamically generated forms and API endpoints
func ExtractDOMForms(ctx context.Context, targetURL string, timeout time.Duration) ([]Form, string, error) {
	hostResolverRule, err := resolveSafeDOMHostRule(targetURL)
	if err != nil {
		return nil, "", fmt.Errorf("refusing to render unsafe DOM target: %w", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		// Security hardening: the Chrome sandbox is the single most important
		// browser defense. It is enabled by default (no-sandbox=false) via the
		// HardenBrowserSandbox toggle. Container/CI environments that run Chrome
		// as root and cannot use the sandbox may set HardenBrowserSandbox=false
		// to fall back to --no-sandbox.
		chromedp.Flag("no-sandbox", !HardenBrowserSandbox),
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("block-new-web-contents", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)
	if hostResolverRule != "" {
		opts = append(opts, chromedp.Flag("host-resolver-rules", hostResolverRule))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	taskCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	timeoutCtx, cancel := context.WithTimeout(taskCtx, timeout)
	defer cancel()

	var extractedForms []Form

	// Intercept XHR/Fetch requests to capture hidden API endpoints
	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			if e.Type == network.ResourceTypeXHR || e.Type == network.ResourceTypeFetch {
				req := e.Request
				if !strings.HasPrefix(req.URL, "data:") {
					var inputs []string

					// Parse Query Parameters
					if idx := strings.Index(req.URL, "?"); idx != -1 {
						query := req.URL[idx+1:]
						pairs := strings.Split(query, "&")
						for _, p := range pairs {
							kv := strings.SplitN(p, "=", 2)
							if len(kv) > 0 && kv[0] != "" {
								inputs = append(inputs, kv[0])
							}
						}
					}

					// Parse JSON PostData. CDP sends entry bytes base64-encoded
					// (see network.PostDataEntry); the raw PostData field, when
					// present, is plain text. Decoded bodies feed both the legacy
					// key heuristic and a full request template that preserves
					// values for single-point mutation.
					bodies, bodyComplete := decodeCDPPostBodies(req)
					for _, body := range bodies {
						// Look for "key": or 'key':
						lines := strings.Split(string(body), ",")
						for _, line := range lines {
							parts := strings.SplitN(line, ":", 2)
							if len(parts) > 0 {
								key := strings.TrimSpace(parts[0])
								key = strings.Trim(key, "{}[]\"'")
								if key != "" {
									inputs = append(inputs, key)
								}
							}
						}
					}

					// Deduplicate
					uniqueInputs := make(map[string]bool)
					var finalInputs []string
					for _, i := range inputs {
						if !uniqueInputs[i] {
							uniqueInputs[i] = true
							finalInputs = append(finalInputs, i)
						}
					}

					// Add inferred endpoints as forms
					captured := Form{
						Action: req.URL,
						Method: req.Method,
						Inputs: finalInputs,
					}
					if len(bodies) == 1 {
						if template, err := FormFromRequest(&BaseRequest{Method: req.Method, URL: req.URL, Body: bodies[0]}); err == nil {
							template.Action = req.URL
							if template.Method == "" {
								template.Method = req.Method
							}
							captured = template
						} else if !bodyComplete {
							captured.Request = &BaseRequest{Method: req.Method, URL: req.URL, Incomplete: true}
						}
					} else if !bodyComplete {
						captured.Request = &BaseRequest{Method: req.Method, URL: req.URL, Incomplete: true}
					}
					extractedForms = append(extractedForms, captured)
				}
			}
		}
	})

	var html string
	var links []string
	err = chromedp.Run(timeoutCtx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second), // Wait for React/Vue to render
		chromedp.OuterHTML("html", &html),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a')).map(a => a.getAttribute('href')).filter(h => h && (h.startsWith('#/') || h.startsWith('/#/')))`, &links),
	)

	if err == nil {
		// Deduplicate and crawl internal SPA routes to trigger their specific XHR API calls
		uniqueLinks := make(map[string]bool)
		for _, link := range links {
			if !uniqueLinks[link] {
				uniqueLinks[link] = true

				routeURL := targetURL
				if !strings.HasSuffix(routeURL, "/") && !strings.HasPrefix(link, "/") {
					routeURL += "/"
				}
				if strings.HasSuffix(routeURL, "/") && strings.HasPrefix(link, "/") {
					link = link[1:]
				}
				routeURL += link

				chromedp.Run(timeoutCtx,
					chromedp.Navigate(routeURL),
					chromedp.Sleep(1*time.Second), // Wait for route specific API calls (like /rest/user/login)
				)
			}
		}
	}

	if err != nil {
		return nil, "", err
	}

	return extractedForms, html, nil
}
