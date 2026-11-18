// Package client is a zero-dependency Go client for a DecisionAI System One server.
//
//	c := client.New("http://127.0.0.1:7480", os.Getenv("DAI_API_TOKEN"))
//	resp, err := c.Decide(ctx, client.Request{
//		State: "Shoes arrived late and in the wrong size",
//		Questions: map[string]client.Question{
//			"dept": client.Choice("Which team should handle this?", client.Opt("returns", "Exchanges"), client.Opt("shipping", "Delivery")),
//			"refund": client.Noul("The customer wants money back"),
//		},
//	})
//	if a := resp.Answers["dept"]; a.Confidence > 0.8 { route(a.Choice) }
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"decisionai/vision"
)

type Question struct {
	Type         string          `json:"type"`
	Instructions string          `json:"instructions"`
	Criteria     json.RawMessage `json:"criteria,omitempty"`
	Task         string          `json:"task,omitempty"`
	Polarity     string          `json:"polarity,omitempty"`
	AbstainKey   string          `json:"abstain_key,omitempty"`
}

// Request.State may be a string or any JSON-serialisable value (structured program state).
type Request struct {
	Images    []vision.Image      `json:"images,omitempty"`
	Model     string              `json:"model,omitempty"`
	State     any                 `json:"state"`
	Questions map[string]Question `json:"questions"`
}

type Answer struct {
	Type          string              `json:"type"`
	Noul          float64             `json:"noul"`
	Choice        string              `json:"choice"`
	Score         float64             `json:"score"`
	Probabilities map[string]float64  `json:"probabilities"`
	Confidence    float64             `json:"confidence"`
	Route         string              `json:"route"`
	Source        string              `json:"source,omitempty"` // expert or general model that answered
	Evidence      []string            `json:"evidence"`
	Abstained     bool                `json:"abstained,omitempty"`
	Reason        string              `json:"reason,omitempty"`
	Checks        []NextCheck         `json:"next_checks,omitempty"`
	References    []EvidenceReference `json:"references,omitempty"`
}

type NextCheck struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Why   string `json:"why"`
	Kind  string `json:"kind"`
}
type EvidenceReference struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	RunID  string `json:"run_id,omitempty"`
}

func ForTask(task string, q Question) Question { q.Task = task; return q }

type Response struct {
	Version   string            `json:"version"`
	Model     string            `json:"model"`
	Backend   string            `json:"backend"`
	Answers   map[string]Answer `json:"answers"`
	ElapsedMs float64           `json:"elapsed_ms"`
	Warnings  []string          `json:"warnings"`
}

type Option struct{ Key, Text string }

func Opt(key, text string) Option { return Option{key, text} }

func ordered(opts []Option) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, o := range opts {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(o.Key)
		v, _ := json.Marshal(o.Text)
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// Noul asks a yes/no question; criteria are optional ("" to omit).
func Noul(instructions string, trueWhen ...string) Question {
	q := Question{Type: "noul", Instructions: instructions}
	if len(trueWhen) > 0 {
		opts := []Option{{"true", trueWhen[0]}}
		if len(trueWhen) > 1 {
			opts = append(opts, Option{"false", trueWhen[1]})
		}
		q.Criteria = ordered(opts)
	}
	return q
}
func Choice(instructions string, opts ...Option) Question {
	return Question{Type: "choice", Instructions: instructions, Criteria: ordered(opts)}
}

// Score levels are ordered as given; numeric keys ("0","1",...) become the score values.
func Score(instructions string, levels ...Option) Question {
	return Question{Type: "score", Instructions: instructions, Criteria: ordered(levels)}
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Decide(ctx context.Context, r Request) (Response, error) {
	var out Response
	body, err := json.Marshal(r)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return out, err
	}
	if res.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.Unmarshal(b, &e)
		return out, fmt.Errorf("decisionai: HTTP %d: %s", res.StatusCode, e.Error)
	}
	return out, json.Unmarshal(b, &out)
}
