// Package s1 is DecisionAI's "System One" interface: unstructured or JSON state in,
// typed probabilistic decisions out. Answers are always one of the caller-declared
// keys (type-safe by construction): the engine never generates free text.
package s1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"decisionai/reasoning"
	"decisionai/vision"
)

const Version = "1.20.0"

const FeatureVersion = "decision-evidence-v2"

// Limits keep a single call bounded and predictable.
const (
	MaxQuestions  = 64
	MaxOptions    = 255
	MaxStateBytes = 256 * 1024
	MaxTextBytes  = 8 * 1024
	MaxQuestionID = 128
	TypeNoul      = "noul"
	TypeChoice    = "choice"
	TypeScore     = "score"
)

// Request mirrors the TypeSafe System One request shape.
type Request struct {
	Images    []vision.Image      `json:"images,omitempty"`
	Model     string              `json:"model,omitempty"`
	State     json.RawMessage     `json:"state"`
	Questions map[string]Question `json:"questions"`
}

// Question is one atomic question. Instructions and criteria values may be a string,
// an object or an array; they are flattened to text deterministically.
type Question struct {
	Claim        *reasoning.Atom `json:"claim,omitempty"`
	Type         string          `json:"type"`
	Instructions json.RawMessage `json:"instructions"`
	Criteria     json.RawMessage `json:"criteria,omitempty"`
	Task         string          `json:"task,omitempty"`
	Polarity     string          `json:"polarity,omitempty"`
	AbstainKey   string          `json:"abstain_key,omitempty"`
}

// Option is one declared answer key with its description (ordered as in the request).
type Option struct {
	Key  string
	Text string
}

// Probs is an ordered probability map: JSON object in declaration order.
type Probs []KV
type KV struct {
	Key string
	P   float64
}

func (p Probs) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(kv.Key)
		b.Write(k)
		b.WriteByte(':')
		b.WriteString(strconv.FormatFloat(round4(kv.P), 'f', -1, 64))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Get returns the probability of key (0 when absent).
func (p Probs) Get(key string) float64 {
	for _, kv := range p {
		if kv.Key == key {
			return kv.P
		}
	}
	return 0
}

// Answer is the typed result for one question. Exactly the fields of its type are set.
type Answer struct {
	Reasoning     *reasoning.Trace  `json:"reasoning,omitempty"`
	Neural        *NeuralInference  `json:"neural,omitempty"`
	Type          string            `json:"type"`
	Calculation   *CalculationTrace `json:"calculation,omitempty"`
	Noul          *float64          `json:"noul,omitempty"`
	Choice        string            `json:"choice,omitempty"`
	Score         *float64          `json:"score,omitempty"`
	Probabilities Probs             `json:"probabilities,omitempty"`
	Confidence    *float64          `json:"confidence,omitempty"`
	// Legend maps each Score level key back to its description (Jev-compatible).
	Legend map[string]string `json:"legend,omitempty"`
	// Route is a default three-path recommendation (auto / review / human).
	// Callers with real stakes should apply their own thresholds.
	Route    string   `json:"route"`
	Evidence []string `json:"evidence,omitempty"`
	// Source says who answered: a specialised expert (smalirole, checks-rule …) or the general backend.
	Source     string              `json:"source,omitempty"`
	Abstained  bool                `json:"abstained,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	Checks     []NextCheck         `json:"next_checks,omitempty"`
	References []EvidenceReference `json:"references,omitempty"`
	// Plan lists the skills of a multi-step request in order
	// ("проанализируй продажи и построй график"); empty for single-step.
	Plan []PlanStep `json:"plan,omitempty"`

	logits []float64 // raw (uncalibrated) logits, used by calibration/eval
	keys   []string
	values []float64 // numeric level values for Score
	fixed  []float64 // expert answers: final probabilities (not temperature-scaled)
}

// PlanStep is one step of a multi-skill plan.
type PlanStep struct {
	Skill  string  `json:"skill"`
	Clause string  `json:"clause"`
	P      float64 `json:"p"`
	File   string  `json:"file,omitempty"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	ModelCalls   int `json:"model_calls"`
	CacheHits    int `json:"cache_hits"`
	// Escalated counts answers re-asked from the remote System Two model (Engine.Escalate).
	Escalated      int     `json:"escalated,omitempty"`
	EscalationCost float64 `json:"escalation_cost,omitempty"`
}

type Response struct {
	Version   string            `json:"version"`
	Model     string            `json:"model"`
	Backend   string            `json:"backend"`
	Answers   map[string]Answer `json:"answers"`
	Usage     Usage             `json:"usage"`
	ElapsedMs float64           `json:"elapsed_ms"`
	Warnings  []string          `json:"warnings,omitempty"`
}

// compiled is a validated, flattened question.
type compiled struct {
	Claim      *reasoning.Atom
	ID         string
	Type       string
	Instr      string
	Options    []Option // choice/score options; noul: optional true/false
	HasCrit    bool
	Task       string
	Polarity   string
	AbstainKey string
}

// Validate checks the request and compiles questions in a stable (sorted id) order.
func (r Request) compile() (string, []compiled, error) {
	if len(bytes.TrimSpace(r.State)) == 0 {
		return "", nil, fmt.Errorf("state is required")
	}
	if len(r.State) > MaxStateBytes {
		return "", nil, fmt.Errorf("state exceeds %d bytes", MaxStateBytes)
	}
	state, err := LinearizeState(r.State)
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(state) == "" {
		return "", nil, fmt.Errorf("state is empty")
	}
	if len(r.Questions) == 0 {
		return "", nil, fmt.Errorf("questions must contain at least one question")
	}
	if len(r.Questions) > MaxQuestions {
		return "", nil, fmt.Errorf("at most %d questions per call", MaxQuestions)
	}
	ids := make([]string, 0, len(r.Questions))
	for id := range r.Questions {
		if id == "" || len(id) > MaxQuestionID {
			return "", nil, fmt.Errorf("question id must be 1..%d bytes", MaxQuestionID)
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]compiled, 0, len(ids))
	for _, id := range ids {
		q := r.Questions[id]
		c := compiled{ID: id, Type: q.Type, Task: q.Task, Polarity: q.Polarity, AbstainKey: q.AbstainKey, Claim: q.Claim}
		if err := validateTask(q); err != nil {
			return "", nil, fmt.Errorf("%s: %w", id, err)
		}
		instr, err := flatten(q.Instructions)
		if err != nil {
			return "", nil, fmt.Errorf("%s.instructions: %v", id, err)
		}
		if strings.TrimSpace(instr) == "" || len(instr) > MaxTextBytes {
			return "", nil, fmt.Errorf("%s.instructions must be 1..%d bytes", id, MaxTextBytes)
		}
		c.Instr = instr
		switch q.Type {
		case TypeNoul:
			if len(bytes.TrimSpace(q.Criteria)) > 0 && string(bytes.TrimSpace(q.Criteria)) != "null" {
				opts, err := orderedOptions(q.Criteria)
				if err != nil {
					return "", nil, fmt.Errorf("%s.criteria: %v", id, err)
				}
				var t, f string
				for _, o := range opts {
					switch o.Key {
					case "true":
						t = o.Text
					case "false":
						f = o.Text
					default:
						return "", nil, fmt.Errorf("%s.criteria: noul accepts only \"true\" and \"false\"", id)
					}
				}
				if strings.TrimSpace(t) == "" && strings.TrimSpace(f) == "" {
					return "", nil, fmt.Errorf("%s.criteria: describe true and/or false", id)
				}
				c.Options = []Option{{"true", t}, {"false", f}}
				c.HasCrit = true
			}
		case TypeChoice, TypeScore:
			// skill_routing expands its options server-side from the skill
			// registry, so empty criteria are legal there (and only there).
			if q.Type == TypeChoice && q.Task == TaskSkillRouting && len(bytes.TrimSpace(q.Criteria)) == 0 {
				break
			}
			opts, err := orderedOptions(q.Criteria)
			if err != nil {
				return "", nil, fmt.Errorf("%s.criteria: %v", id, err)
			}
			if len(opts) < 2 || len(opts) > MaxOptions {
				return "", nil, fmt.Errorf("%s.criteria must declare 2..%d options", id, MaxOptions)
			}
			for i := range opts {
				if opts[i].Text == "" {
					opts[i].Text = humanKey(opts[i].Key)
				}
			}
			c.Options = opts
			c.HasCrit = true
			if c.AbstainKey != "" {
				found := false
				for _, o := range opts {
					found = found || o.Key == c.AbstainKey
				}
				if !found {
					return "", nil, fmt.Errorf("%s.abstain_key must be a declared option", id)
				}
			}
		default:
			return "", nil, fmt.Errorf("%s.type must be noul, choice or score", id)
		}
		out = append(out, c)
	}
	return state, out, nil
}

// orderedOptions parses a JSON object preserving key order, rejecting duplicates.
func orderedOptions(raw json.RawMessage) ([]Option, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("must be a JSON object")
	}
	if d, ok := t.(json.Delim); ok && d == '[' {
		// Jev-style ordered levels: ["Calm", "Frustrated", "Very angry"] -> keys "0", "1", "2"
		var out []Option
		for i := 0; dec.More(); i++ {
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, err
			}
			txt, err := flatten(v)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %v", i, err)
			}
			if len(txt) > MaxTextBytes {
				return nil, fmt.Errorf("[%d]: description too long", i)
			}
			out = append(out, Option{Key: strconv.Itoa(i), Text: txt})
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return out, nil
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("must be a JSON object of option -> description (or an array of levels)")
	}
	seen := map[string]bool{}
	var out []Option
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		if strings.TrimSpace(k) == "" || len(k) > 256 {
			return nil, fmt.Errorf("option key must be 1..256 bytes")
		}
		if seen[k] {
			return nil, fmt.Errorf("duplicate option %q", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		txt, err := flatten(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", k, err)
		}
		if len(txt) > MaxTextBytes {
			return nil, fmt.Errorf("%s: description too long", k)
		}
		out = append(out, Option{Key: k, Text: txt})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return out, nil
}

// flatten turns a string / object / array / null into deterministic text.
func flatten(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s), nil
	}
	var b strings.Builder
	flattenAny(&b, "", v)
	return strings.TrimSpace(b.String()), nil
}

func flattenAny(b *strings.Builder, prefix string, v any) {
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) == "" {
			return
		}
		if prefix != "" {
			b.WriteString(prefix + ": ")
		}
		b.WriteString(x)
		b.WriteString(". ")
	case []any:
		for _, e := range x {
			flattenAny(b, prefix, e)
		}
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			p := humanKey(k)
			if prefix != "" {
				p = prefix + " " + p
			}
			flattenAny(b, p, x[k])
		}
	case nil:
	default:
		if prefix != "" {
			b.WriteString(prefix + ": ")
		}
		b.WriteString(fmt.Sprint(x))
		b.WriteString(". ")
	}
}

func humanKey(k string) string {
	return strings.TrimSpace(strings.NewReplacer("_", " ", "-", " ").Replace(k))
}
