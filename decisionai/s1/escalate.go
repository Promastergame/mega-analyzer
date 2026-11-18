package s1

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Escalator is the "System Two" step of a cascade: answers that System One is not
// sure about (route review/human by default) are re-asked from a remote decision
// model that speaks the same wire format — TypeSafe Jev (`typesafe/jev-1.13`) or
// Respan Span-01 Lite (`respan/span-01-lite:free`, noul only) through OpenRouter's
// decisions API. Confident answers never leave the machine; on any remote error the
// local answer is kept and the failure is recorded in its evidence.
type Escalator struct {
	URL      string // default https://openrouter.ai/api/alpha/decisions
	Key      string
	Model    string
	NoulOnly bool            // Respan models score noul behaviours only
	On       map[string]bool // routes to escalate; default review + human
	Timeout  time.Duration   // default 20 s
	Client   *http.Client

	// Log, when set, appends every remote answer as a labelled example
	// ({group, request, labels, model}, the format of data/distill/*.labelled.jsonl),
	// so System Two's answers become training data for System One (data flywheel).
	// The log also warms the cache: identical questions are answered from it offline.
	Log string

	mu    sync.Mutex
	cost  float64
	n     int
	hits  int
	cache map[string]remoteAnswer // our keys; bounded by MaxEscalationCache
}

// MaxEscalationCache bounds the in-memory answer cache.
const MaxEscalationCache = 100000

func cacheKey(model string, state json.RawMessage, q Question) string {
	h := sha256.New()
	qb, _ := json.Marshal(q)
	h.Write([]byte(model))
	h.Write([]byte{0})
	h.Write(bytes.TrimSpace(state))
	h.Write([]byte{0})
	h.Write(qb)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

type logRow struct {
	Group   string                     `json:"group"`
	Model   string                     `json:"model"`
	Keys    map[string]string          `json:"cache_keys"`
	Request Request                    `json:"request"`
	Labels  map[string]json.RawMessage `json:"labels"`
}

// LoadLog warms the cache from an existing escalation log (missing file = empty).
func (x *Escalator) LoadLog() error {
	f, err := os.Open(x.Log)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	x.mu.Lock()
	defer x.mu.Unlock()
	for sc.Scan() {
		var row logRow
		if json.Unmarshal(sc.Bytes(), &row) != nil {
			continue
		}
		for id, k := range row.Keys {
			if ra, ok := labelToAnswer(row.Labels[id]); ok {
				x.put(k, ra)
			}
		}
	}
	return sc.Err()
}

func (x *Escalator) put(k string, ra remoteAnswer) {
	if x.cache == nil {
		x.cache = map[string]remoteAnswer{}
	}
	if len(x.cache) >= MaxEscalationCache {
		for old := range x.cache { // drop an arbitrary entry: simple and bounded
			delete(x.cache, old)
			break
		}
	}
	x.cache[k] = ra
}

func labelToAnswer(raw json.RawMessage) (remoteAnswer, bool) {
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return remoteAnswer{Noul: &f}, true
	}
	var d map[string]float64
	if json.Unmarshal(raw, &d) == nil && len(d) > 0 {
		return remoteAnswer{Probabilities: d}, true
	}
	return remoteAnswer{}, false
}

// answerToLabel stores a merged answer in our own keys.
func answerToLabel(a Answer) json.RawMessage {
	if a.Type == TypeNoul && a.Noul != nil {
		b, _ := json.Marshal(round4(*a.Noul))
		return b
	}
	d := map[string]float64{}
	for _, kv := range a.Probabilities {
		d[kv.Key] = round4(kv.P)
	}
	b, _ := json.Marshal(d)
	return b
}

// Stats reports escalated answers, cache hits and remote cost so far.
func (x *Escalator) Stats() (escalated, cacheHits int, cost float64) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.n, x.hits, x.cost
}

// DefaultEscalationURL is OpenRouter's decisions endpoint.
const DefaultEscalationURL = "https://openrouter.ai/api/alpha/decisions"

// NewEscalator configures a cascade to model; respan/* models are noul-only.
func NewEscalator(model, key string) *Escalator {
	return &Escalator{URL: DefaultEscalationURL, Key: key, Model: model, NoulOnly: strings.HasPrefix(model, "respan/"),
		On: map[string]bool{"review": true, "human": true}}
}

// Spent reports the number of escalated questions and the remote cost so far (USD).
func (x *Escalator) Spent() (int, float64) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.n, x.cost
}

type remoteAnswer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul"`
	Choice        string             `json:"choice"`
	Score         *float64           `json:"score"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    *float64           `json:"confidence"`
}

type remoteResponse struct {
	Model   string                  `json:"model"`
	Answers map[string]remoteAnswer `json:"answers"`
	Usage   struct {
		Cost float64 `json:"cost"`
	} `json:"usage"`
	Error json.RawMessage `json:"error"`
}

// scoreKeys returns the declared score keys in level order (numeric when possible).
func scoreKeys(crit map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(crit))
	for k := range crit {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, ea := strconv.ParseFloat(keys[i], 64)
		b, eb := strconv.ParseFloat(keys[j], 64)
		if ea == nil && eb == nil {
			return a < b
		}
		return keys[i] < keys[j]
	})
	return keys
}

// wire builds the remote request for the selected questions; levels[id] maps the
// remote score index ("0".."n-1") back to the caller's keys.
func (x *Escalator) wire(r Request, ids []string) ([]byte, map[string][]string, error) {
	qs := map[string]any{}
	levels := map[string][]string{}
	for _, id := range ids {
		q := r.Questions[id]
		j := map[string]any{"type": q.Type, "instructions": json.RawMessage(q.Instructions)}
		if len(q.Criteria) > 0 {
			var obj map[string]json.RawMessage
			if q.Type == TypeScore && json.Unmarshal(q.Criteria, &obj) == nil {
				keys := scoreKeys(obj)
				arr := make([]json.RawMessage, len(keys))
				for i, k := range keys {
					arr[i] = obj[k]
				}
				j["criteria"], levels[id] = arr, keys
			} else {
				j["criteria"] = json.RawMessage(q.Criteria)
				var arr []json.RawMessage
				if q.Type == TypeScore && json.Unmarshal(q.Criteria, &arr) == nil {
					for i := range arr {
						levels[id] = append(levels[id], strconv.Itoa(i))
					}
				}
			}
		}
		qs[id] = j
	}
	var state any = json.RawMessage(r.State)
	var s string
	if json.Unmarshal(r.State, &s) != nil && x.NoulOnly {
		state = string(r.State) // Respan accepts a plain string or a chat transcript only
	}
	b, err := json.Marshal(map[string]any{"model": x.Model, "state": state, "questions": qs})
	return b, levels, err
}

func (x *Escalator) wants(q Question, a Answer) bool {
	if a.Plan != nil || q.Task == TaskSkillRouting {
		return false // skill routing stays local: the remote model does not know the registry
	}
	if x.NoulOnly && q.Type != TypeNoul {
		return false
	}
	on := x.On
	if on == nil {
		on = map[string]bool{"review": true, "human": true}
	}
	return on["all"] || on[a.Route]
}

// Apply escalates the uncertain answers of resp in one remote call.
func (x *Escalator) Apply(ctx context.Context, r Request, resp *Response) {
	var ids []string
	for id, a := range resp.Answers {
		if a.Neural != nil || a.Reasoning != nil || a.Source == "reasoning-proof" {
			continue
		} // preserve explicitly requested local inference/proof provenance
		if q, ok := r.Questions[id]; ok && x.wants(q, a) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	sort.Strings(ids)
	// 1. answers already known (this process or the warm log) cost nothing
	keys := map[string]string{}
	remote := ids[:0:0]
	for _, id := range ids {
		k := cacheKey(x.Model, r.State, r.Questions[id])
		keys[id] = k
		x.mu.Lock()
		ra, ok := x.cache[k]
		x.mu.Unlock()
		a := resp.Answers[id]
		if ok && mergeRemote(&a, ra, nil) {
			a.Source = "escalated-cache:" + x.Model
			resp.Answers[id] = a
			x.mu.Lock()
			x.hits++
			x.mu.Unlock()
			resp.Usage.Escalated++
			continue
		}
		remote = append(remote, id)
	}
	ids = remote
	if len(ids) == 0 {
		return
	}
	fail := func(err error) {
		for _, id := range ids {
			a := resp.Answers[id]
			a.Evidence = append(a.Evidence, "escalation to "+x.Model+" failed: "+err.Error())
			resp.Answers[id] = a
		}
	}
	body, levels, err := x.wire(r, ids)
	if err != nil {
		fail(err)
		return
	}
	to := x.Timeout
	if to == 0 {
		to = 20 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	url := x.URL
	if url == "" {
		url = DefaultEscalationURL
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		fail(err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if x.Key != "" {
		req.Header.Set("Authorization", "Bearer "+x.Key)
	}
	cl := x.Client
	if cl == nil {
		cl = http.DefaultClient
	}
	hr, err := cl.Do(req)
	if err != nil {
		fail(err)
		return
	}
	defer hr.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(hr.Body, 1<<20))
	var rr remoteResponse
	if hr.StatusCode != 200 || json.Unmarshal(raw, &rr) != nil || len(rr.Error) > 0 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		fail(fmt.Errorf("HTTP %d %s", hr.StatusCode, msg))
		return
	}
	name := rr.Model
	if name == "" {
		name = x.Model
	}
	n := 0
	row := logRow{Group: "esc-" + keys[ids[0]], Model: name, Keys: map[string]string{}, Labels: map[string]json.RawMessage{},
		Request: Request{State: r.State, Questions: map[string]Question{}}}
	for _, id := range ids {
		ra, ok := rr.Answers[id]
		a := resp.Answers[id]
		if !ok || !mergeRemote(&a, ra, levels[id]) {
			a.Evidence = append(a.Evidence, "escalation to "+name+": no usable answer")
			resp.Answers[id] = a
			continue
		}
		a.Source = "escalated:" + name
		resp.Answers[id] = a
		n++
		lab := answerToLabel(a)
		if ra, ok := labelToAnswer(lab); ok {
			x.mu.Lock()
			x.put(keys[id], ra)
			x.mu.Unlock()
		}
		row.Keys[id], row.Labels[id], row.Request.Questions[id] = keys[id], lab, r.Questions[id]
	}
	if x.Log != "" && n > 0 {
		if b, err := json.Marshal(row); err == nil {
			x.mu.Lock()
			if f, err := os.OpenFile(x.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				f.Write(append(b, '\n'))
				f.Close()
			}
			x.mu.Unlock()
		}
	}
	x.mu.Lock()
	x.n += n
	x.cost += rr.Usage.Cost
	x.mu.Unlock()
	resp.Usage.Escalated += n
	resp.Usage.EscalationCost += rr.Usage.Cost
}

// mergeRemote replaces the local distribution with the remote one, keeping the
// caller's keys and the local answer as evidence. Abstain keys stay possible.
func mergeRemote(a *Answer, ra remoteAnswer, levels []string) bool {
	local := describeLocal(*a)
	switch a.Type {
	case TypeNoul:
		if ra.Noul == nil || math.IsNaN(*ra.Noul) {
			return false
		}
		p := clamp01(*ra.Noul)
		a.Noul = &p
		a.Probabilities = Probs{{"true", p}, {"false", 1 - p}}
		a.fixed = []float64{p, 1 - p}
		a.Route = DefaultRoute(NoulCertainty(p))
	case TypeChoice, TypeScore:
		if len(ra.Probabilities) == 0 || len(a.keys) == 0 {
			return false
		}
		dist := make([]float64, len(a.keys))
		sum := 0.0
		for i, k := range a.keys {
			rk := k
			if a.Type == TypeScore && levels != nil {
				for li, lk := range levels {
					if lk == k {
						rk = strconv.Itoa(li)
					}
				}
			}
			dist[i] = math.Max(0, ra.Probabilities[rk])
			sum += dist[i]
		}
		if sum <= 0 {
			return false
		}
		best := 0
		pr := make(Probs, len(dist))
		for i := range dist {
			dist[i] /= sum
			pr[i] = KV{a.keys[i], dist[i]}
			if dist[i] > dist[best] {
				best = i
			}
		}
		a.Probabilities, a.fixed = pr, dist
		conf := dist[best]
		if ra.Confidence != nil {
			conf = clamp01(*ra.Confidence)
		}
		a.Confidence = &conf
		if a.Type == TypeChoice {
			a.Choice = a.keys[best]
		} else {
			ev := 0.0
			for i, v := range a.values {
				if i < len(dist) {
					ev += v * dist[i]
				}
			}
			if len(a.values) != len(dist) && ra.Score != nil {
				ev = *ra.Score
			}
			a.Score = &ev
		}
		a.Route = DefaultRoute(conf)
		a.Abstained, a.Reason = false, ""
	default:
		return false
	}
	a.Evidence = append(a.Evidence, local)
	return true
}

func describeLocal(a Answer) string {
	switch {
	case a.Noul != nil:
		return fmt.Sprintf("System One said %.2f (route %s)", *a.Noul, a.Route)
	case a.Choice != "":
		return fmt.Sprintf("System One said %s (route %s)", a.Choice, a.Route)
	case a.Score != nil:
		return fmt.Sprintf("System One said %.2f (route %s)", *a.Score, a.Route)
	}
	return "System One abstained (route " + a.Route + ")"
}
