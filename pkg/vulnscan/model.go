package vulnscan

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This file holds the core data model for the pipeline-oriented scanner: the
// attack-surface / injection-point representation the active checks operate on,
// the response signature used for differential and timing analysis, and the
// interaction ledger used for forensic recording. It is the foundation the
// engine and every checks_*.go build on.

// SurfaceType classifies the kind of attack surface discovered.
type SurfaceType string

const (
	SurfaceFormSubmit       SurfaceType = "form_submit"
	SurfaceAPIEndpoint      SurfaceType = "api_endpoint"
	SurfaceGraphQLOp        SurfaceType = "graphql_operation"
	SurfaceWebSocket        SurfaceType = "websocket"
	SurfaceHeaderReflection SurfaceType = "header_reflection"
)

// PointLocation indicates where in an HTTP request an injection point resides.
type PointLocation string

const (
	LocationQueryParam  PointLocation = "query_param"
	LocationBody        PointLocation = "body"
	LocationHeader      PointLocation = "header"
	LocationPathSegment PointLocation = "path_segment"
	LocationCookie      PointLocation = "cookie"
	LocationJSONField   PointLocation = "json_field"
)

// InferredType represents the data type the scanner infers for an injection point.
type InferredType string

const (
	TypeString  InferredType = "string"
	TypeNumeric InferredType = "numeric"
	TypeEmail   InferredType = "email"
	TypeURL     InferredType = "url"
	TypeToken   InferredType = "token"
	TypeUUID    InferredType = "uuid"
	TypeEnum    InferredType = "enum"
	TypeUnknown InferredType = "unknown"
)

// BaseRequest is a lightweight, immutable description of the request an attack
// surface was discovered from. Checks clone it (never mutate it) to build
// per-payload probe requests. It is deliberately not an *http.Request so it can
// be copied by value alongside its AttackSurface across pipeline channels.
type BaseRequest struct {
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         []byte            `json:"body,omitempty"`
	HeaderValues http.Header       `json:"header_values,omitempty"`
	Incomplete   bool              `json:"incomplete,omitempty"`
}

// InjectionPoint represents a single testable parameter in an attack surface.
type InjectionPoint struct {
	Name     string        `json:"name"`
	Location PointLocation `json:"location"`
	DataType InferredType  `json:"data_type"`
	Original string        `json:"original_value,omitempty"`
	// Index identifies one occurrence of a repeated query/form parameter.
	Index int `json:"index,omitempty"`
}

// AttackSurface represents a testable endpoint with its injectable parameters.
type AttackSurface struct {
	ID              string           `json:"id"`
	Type            SurfaceType      `json:"type"`
	Method          string           `json:"method"`
	URL             string           `json:"url"`
	Enctype         string           `json:"enctype,omitempty"`
	InjectionPoints []InjectionPoint `json:"injection_points"`
	RequiresAuth    bool             `json:"requires_auth,omitempty"`

	// BaseRequest carries the discovered request template used to build probes.
	BaseRequest *BaseRequest `json:"base_request,omitempty"`
}

// AttackSurfacesFromForms converts discovered legacy Forms into attack surfaces
// ready for the injection stage.
func AttackSurfacesFromForms(forms []Form) []AttackSurface {
	surfaces := make([]AttackSurface, 0, len(forms))
	for _, f := range forms {
		surfaces = append(surfaces, attackSurfaceFromForm(f))
	}
	return surfaces
}

// attackSurfaceFromForm converts a single legacy Form into an AttackSurface.
func attackSurfaceFromForm(f Form) AttackSurface {
	method := strings.ToUpper(f.Method)
	if method == "" {
		method = "GET"
	}
	points := make([]InjectionPoint, 0, len(f.Inputs))
	for _, name := range f.Inputs {
		loc := LocationBody
		if method == "GET" {
			loc = LocationQueryParam
		}
		points = append(points, InjectionPoint{Name: name, Location: loc, DataType: InferInputType(name)})
	}
	if f.Points != nil {
		points = append([]InjectionPoint(nil), f.Points...)
	}
	base := f.Request.Clone()
	if base == nil {
		base = &BaseRequest{Method: method, URL: f.Action}
	}
	return AttackSurface{
		ID:              generateSurfaceID(),
		Type:            SurfaceFormSubmit,
		Method:          method,
		URL:             f.Action,
		Enctype:         f.Enctype,
		InjectionPoints: points,
		BaseRequest:     base,
	}
}

// ToForm converts an AttackSurface back to a legacy Form.
func (as AttackSurface) ToForm() Form {
	inputs := make([]string, 0, len(as.InjectionPoints))
	for _, p := range as.InjectionPoints {
		inputs = append(inputs, p.Name)
	}
	return Form{Action: as.URL, Method: as.Method, Enctype: as.Enctype, Inputs: inputs, Request: as.BaseRequest.Clone(), Points: append([]InjectionPoint(nil), as.InjectionPoints...)}
}

// InferInputType guesses the data type from a parameter name.
func InferInputType(name string) InferredType {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "email") || strings.Contains(lower, "mail"):
		return TypeEmail
	case strings.Contains(lower, "url") || strings.Contains(lower, "uri") || strings.Contains(lower, "link") || strings.Contains(lower, "href"):
		return TypeURL
	case strings.Contains(lower, "uuid") || strings.Contains(lower, "guid"):
		return TypeUUID
	case strings.Contains(lower, "token") || strings.Contains(lower, "csrf") || strings.Contains(lower, "nonce") || strings.Contains(lower, "session"):
		return TypeToken
	case strings.Contains(lower, "id") || strings.Contains(lower, "num") || strings.Contains(lower, "count") || strings.Contains(lower, "amount") || strings.Contains(lower, "price") || strings.Contains(lower, "quantity"):
		return TypeNumeric
	default:
		return TypeString
	}
}

func generateSurfaceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ResponseSignature is a compact fingerprint of an HTTP response used for
// differential comparison (baseline vs. injected) and timing analysis.
type ResponseSignature struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	BodyLen       int    `json:"body_len"`
	ContentType   string `json:"content_type,omitempty"`
	TimingMs      int64  `json:"timing_ms"`
}

// ComputeResponseSignature builds a ResponseSignature from the raw parts of a
// response plus the measured round-trip latency in milliseconds.
func ComputeResponseSignature(status int, header http.Header, body []byte, elapsedMs int64) *ResponseSignature {
	sig := &ResponseSignature{
		StatusCode: status,
		BodyLen:    len(body),
		TimingMs:   elapsedMs,
	}
	if header != nil {
		sig.ContentType = header.Get("Content-Type")
	}
	sig.ContentLength = len(body)
	return sig
}

// TimingIsAnomalous reports whether an observed latency is a statistically
// significant outlier above a baseline sample. It combines two guards to keep
// false positives low on jittery targets:
//   - the observed value must exceed mean + k*stddev of the baseline, and
//   - the absolute delta over the baseline mean must be at least minDeltaMs.
//
// A baseline with fewer than two samples cannot yield a meaningful stddev, so
// the function falls back to the minDeltaMs guard alone.
func TimingIsAnomalous(baseline []int64, observed int64, k float64, minDeltaMs int64) bool {
	if len(baseline) == 0 {
		return false
	}
	var sum float64
	for _, v := range baseline {
		sum += float64(v)
	}
	mean := sum / float64(len(baseline))
	delta := float64(observed) - mean
	if delta < float64(minDeltaMs) {
		return false
	}
	if len(baseline) < 2 {
		return delta >= float64(minDeltaMs)
	}
	var variance float64
	for _, v := range baseline {
		d := float64(v) - mean
		variance += d * d
	}
	variance /= float64(len(baseline) - 1)
	stddev := math.Sqrt(variance)
	if stddev == 0 {
		// No observed jitter: rely on the absolute-delta guard.
		return delta >= float64(minDeltaMs)
	}
	return delta >= k*stddev
}

// Interaction records a single HTTP request/response pair for forensic purposes.
type Interaction struct {
	ID        uint64
	Request   *http.Request
	Response  *http.Response
	Body      []byte
	Duration  time.Duration
	Timestamp time.Time
	CheckID   string
	Tags      []string
}

// Ledger records HTTP interactions during a scan as a bounded ring buffer.
// Record is O(1): once full, the oldest slot is overwritten in place instead
// of shifting the slice.
type Ledger struct {
	mu      sync.Mutex
	entries []Interaction
	head    int // index of the oldest entry
	size    int
	nextID  uint64
	maxSize int
}

// NewLedger creates a Ledger that retains at most maxSize interactions.
func NewLedger(maxSize int) *Ledger {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &Ledger{entries: make([]Interaction, maxSize), maxSize: maxSize}
}

// Record stores an interaction, evicting the oldest entry when full, and
// returns the assigned interaction ID.
func (l *Ledger) Record(i Interaction) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	i.ID = l.nextID
	if i.Timestamp.IsZero() {
		i.Timestamp = time.Now()
	}
	idx := (l.head + l.size) % l.maxSize
	if l.size == l.maxSize {
		// Full: overwrite the oldest slot and advance the head.
		l.head = (l.head + 1) % l.maxSize
	} else {
		l.size++
	}
	l.entries[idx] = i
	return i.ID
}

// FindByCheck returns all recorded interactions tagged with the given check
// ID, in chronological order.
func (l *Ledger) FindByCheck(checkID string) []Interaction {
	l.mu.Lock()
	defer l.mu.Unlock()
	var result []Interaction
	for k := 0; k < l.size; k++ {
		e := l.entries[(l.head+k)%l.maxSize]
		if e.CheckID == checkID {
			result = append(result, e)
		}
	}
	return result
}

// Count returns the number of interactions currently retained.
func (l *Ledger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.size
}
