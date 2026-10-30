// Package decisionai connects the analyzer to a separately installed local
// DecisionAI System One service. It never starts a model or applies a decision.
package decisionai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultURL       = "http://127.0.0.1:7480"
	MaxRequestBytes  = 512 << 10
	MaxResponseBytes = 1 << 20
)

type Question struct {
	Type         string          `json:"type"`
	Instructions json.RawMessage `json:"instructions"`
	Criteria     json.RawMessage `json:"criteria,omitempty"`
	Task         string          `json:"task,omitempty"`
	Polarity     string          `json:"polarity,omitempty"`
	AbstainKey   string          `json:"abstain_key,omitempty"`
}

type Request struct {
	Model     string              `json:"model,omitempty"`
	State     json.RawMessage     `json:"state"`
	Questions map[string]Question `json:"questions"`
}

type NextCheck struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Why   string `json:"why"`
	Kind  string `json:"kind"`
}

type Reference struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	RunID  string `json:"run_id,omitempty"`
}

type Answer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Route         string             `json:"route"`
	Source        string             `json:"source,omitempty"`
	Evidence      []string           `json:"evidence,omitempty"`
	Abstained     bool               `json:"abstained,omitempty"`
	Reason        string             `json:"reason,omitempty"`
	Checks        []NextCheck        `json:"next_checks,omitempty"`
	References    []Reference        `json:"references,omitempty"`
	Legend        map[string]string  `json:"legend,omitempty"`
	Plan          json.RawMessage    `json:"plan,omitempty"`
}

type Response struct {
	Version   string            `json:"version"`
	Model     string            `json:"model"`
	Backend   string            `json:"backend"`
	Answers   map[string]Answer `json:"answers"`
	ElapsedMS float64           `json:"elapsed_ms"`
	Warnings  []string          `json:"warnings,omitempty"`
	Usage     json.RawMessage   `json:"usage,omitempty"`
}

// NormalizeURL accepts only loopback destinations. localhost is pinned to an
// IP; no name resolution, environment proxy or redirects can move scan data.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("DecisionAI URL must be an http(s) loopback origin without credentials, path, query or fragment")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("DecisionAI URL must use localhost or a loopback IP")
	}
	port := u.Port()
	u.Host = ip.String()
	if strings.Contains(u.Host, ":") {
		u.Host = "[" + u.Host + "]"
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("DecisionAI port must be between 1 and 65535")
		}
		u.Host = net.JoinHostPort(ip.String(), port)
	}
	u.Path, u.RawPath = "", ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

type Client struct {
	url   string
	token string
	http  *http.Client
}

func New(rawURL, token string) (*Client, error) {
	base, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{url: base, token: token, http: &http.Client{
		Timeout:       5 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	b, err := readBounded(r, MaxRequestBytes)
	if err != nil {
		return req, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&req); err != nil {
		return req, fmt.Errorf("DecisionAI request: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return req, fmt.Errorf("DecisionAI request must contain one JSON object")
	}
	return req, validateRequest(req)
}

func validateRequest(req Request) error {
	if len(req.State) == 0 || len(req.State) > 256<<10 || !json.Valid(req.State) || string(bytes.TrimSpace(req.State)) == "null" {
		return fmt.Errorf("DecisionAI state must be non-null JSON, at most 256 KiB")
	}
	if len(req.Questions) == 0 || len(req.Questions) > 64 {
		return fmt.Errorf("DecisionAI requires 1..64 questions")
	}
	for id, q := range req.Questions {
		if id == "" || len(id) > 128 || len(q.Instructions) == 0 || len(q.Instructions) > 8<<10 || !json.Valid(q.Instructions) {
			return fmt.Errorf("DecisionAI question ID or instructions invalid")
		}
		if q.Type != "noul" && q.Type != "choice" && q.Type != "score" {
			return fmt.Errorf("DecisionAI question %q has unsupported type", id)
		}
		if q.Type != "noul" {
			var opts map[string]json.RawMessage
			if json.Unmarshal(q.Criteria, &opts) != nil || len(opts) < 2 || len(opts) > 255 {
				return fmt.Errorf("DecisionAI question %q requires 2..255 criteria", id)
			}
		}
	}
	return nil
}

func (c *Client) Decide(ctx context.Context, req Request) (Response, error) {
	var out Response
	if err := validateRequest(req); err != nil {
		return out, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	if len(b) > MaxRequestBytes {
		return out, fmt.Errorf("DecisionAI request exceeds 512 KiB")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/decide", bytes.NewReader(b))
	if err != nil {
		return out, err
	}
	r.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return out, fmt.Errorf("DecisionAI unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("DecisionAI returned HTTP %d", resp.StatusCode)
	}
	b, err = readBounded(resp.Body, MaxResponseBytes)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(b, &out); err != nil {
		return Response{}, fmt.Errorf("invalid DecisionAI response: %w", err)
	}
	if err = validateResponse(req, out); err != nil {
		return Response{}, err
	}
	return out, nil
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("DecisionAI JSON exceeds %d bytes", max)
	}
	return b, nil
}

func probability(p float64) bool { return !math.IsNaN(p) && !math.IsInf(p, 0) && p >= 0 && p <= 1 }

func validateResponse(req Request, resp Response) error {
	if resp.Version == "" || resp.Backend == "" || len(resp.Answers) != len(req.Questions) {
		return fmt.Errorf("incomplete DecisionAI response")
	}
	for id, q := range req.Questions {
		a, ok := resp.Answers[id]
		if !ok || a.Type != q.Type {
			return fmt.Errorf("DecisionAI answer %q missing or wrong type", id)
		}
		if a.Route != "auto" && a.Route != "review" && a.Route != "human" {
			return fmt.Errorf("DecisionAI answer %q has invalid route", id)
		}
		if a.Confidence != nil && !probability(*a.Confidence) {
			return fmt.Errorf("DecisionAI answer %q has invalid confidence", id)
		}
		if q.Type == "noul" {
			if a.Noul == nil || !probability(*a.Noul) || a.Score != nil || a.Choice != "" {
				return fmt.Errorf("DecisionAI answer %q has invalid noul", id)
			}
			continue
		}
		var opts map[string]json.RawMessage
		_ = json.Unmarshal(q.Criteria, &opts)
		if a.Noul != nil || a.Confidence == nil || len(a.Probabilities) != len(opts) {
			return fmt.Errorf("DecisionAI answer %q has invalid distribution", id)
		}
		sum := 0.0
		for key := range opts {
			p, ok := a.Probabilities[key]
			if !ok || !probability(p) {
				return fmt.Errorf("DecisionAI answer %q has invalid probability", id)
			}
			sum += p
		}
		// The service rounds each probability to four decimal places.
		if math.Abs(sum-1) > float64(len(opts))*0.000051 {
			return fmt.Errorf("DecisionAI answer %q probabilities do not sum to one", id)
		}
		if q.Type == "choice" {
			if _, ok := opts[a.Choice]; !ok || a.Score != nil {
				return fmt.Errorf("DecisionAI answer %q chose an undeclared option", id)
			}
		} else if a.Score == nil || math.IsNaN(*a.Score) || math.IsInf(*a.Score, 0) || a.Choice != "" {
			return fmt.Errorf("DecisionAI answer %q has invalid score", id)
		} else {
			lo, hi := scoreBounds(opts)
			if *a.Score < lo-0.000051 || *a.Score > hi+0.000051 {
				return fmt.Errorf("DecisionAI answer %q has score outside the declared scale", id)
			}
		}
	}
	return nil
}

func scoreBounds(opts map[string]json.RawMessage) (float64, float64) {
	lo, hi := math.Inf(1), math.Inf(-1)
	for key := range opts {
		n, err := strconv.ParseFloat(strings.TrimSpace(key), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			// System One uses declaration indexes for nonnumeric scales.
			return 0, float64(len(opts) - 1)
		}
		lo, hi = math.Min(lo, n), math.Max(hi, n)
	}
	return lo, hi
}
