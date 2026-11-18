package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"decisionai/vision"
)

const collectModelMaxClasses = 64
const collectModelMaxSamples = 4096
const collectModelMinSamples = 3

// Welford statistics use fixed memory per class; image bytes never enter the model.
type collectPrototype struct {
	N          int                 `json:"samples"`
	Images     int                 `json:"images"`
	Mean       [32]float64         `json:"-"`
	M2         [32]float64         `json:"-"`
	seenImages map[string]struct{}
}

func (p *collectPrototype) add(v vision.VectorV1, imageHash string) {
	if p.seenImages == nil {
		p.seenImages = make(map[string]struct{})
	}
	if _, seen := p.seenImages[imageHash]; !seen {
		p.seenImages[imageHash] = struct{}{}
		p.Images++
	}
	p.N++
	for i, b := range v {
		x := float64(b) / 255
		d := x - p.Mean[i]
		p.Mean[i] += d / float64(p.N)
		p.M2[i] += d * (x - p.Mean[i])
	}
}

func (p *collectPrototype) ready() bool {
	// Several crops or repeated votes from one image are correlated examples.
	// Require both region labels and independent image identities.
	return p.N >= collectModelMinSamples && p.Images >= collectModelMinSamples
}

func (p *collectPrototype) distance(v vision.VectorV1) float64 {
	if p.N == 0 {
		return math.Inf(1)
	}
	var sum float64
	for i, b := range v {
		variance := .0064 // noise floor: 8% of a normalized feature
		if p.N > 1 {
			variance = math.Max(variance, p.M2[i]/float64(p.N-1))
		}
		d := float64(b)/255 - p.Mean[i]
		sum += d * d / variance
	}
	return math.Sqrt(sum / 32)
}

type collectClassModel struct {
	Positive collectPrototype `json:"positive"`
	Negative collectPrototype `json:"negative"`
}

type collectVectorModel struct {
	Classes     map[string]*collectClassModel
	Adult, Safe collectPrototype
	Seen        map[string]bool
	AgeSeen     map[string]bool
	Samples     int
	Limited     bool
	Records     map[string]collectRecord
	Sequence    uint64
}

func newCollectVectorModel() *collectVectorModel {
	return &collectVectorModel{Classes: make(map[string]*collectClassModel), Seen: make(map[string]bool), AgeSeen: make(map[string]bool), Records: make(map[string]collectRecord)}
}

// A training sample is a region, not an image/vote pair. The append-only log
// is replayed with last-write-wins semantics, including corrections without vectors.
type collectRecord struct {
	Feedback collectFeedback
	Sequence uint64
}

func collectRegionKey(f collectFeedback) string {
	return fmt.Sprintf("%s/%d/%d/%d/%d/%d/%d", strings.ToLower(f.ImgSHA256), f.Width, f.Height, f.Box.X, f.Box.Y, f.Box.W, f.Box.H)
}
func collectSampleKey(f collectFeedback) string { return collectRegionKey(f) + "/" + f.Box.Class }

func (m *collectVectorModel) rebuild() {
	m.Classes = make(map[string]*collectClassModel)
	m.Seen = make(map[string]bool)
	m.AgeSeen = make(map[string]bool)
	m.Adult, m.Safe = collectPrototype{}, collectPrototype{}
	keys := make([]string, 0, len(m.Records))
	for key := range m.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys) // Stable floating-point accumulation on disk replay.
	ages := make(map[string]collectRecord)
	for _, key := range keys {
		rec := m.Records[key]
		f := rec.Feedback
		p := m.Classes[f.Box.Class]
		if p == nil {
			p = &collectClassModel{}
			m.Classes[f.Box.Class] = p
		}
		m.Seen[key] = true
		if f.Vote == 1 {
			p.Positive.add(*f.Vector, f.ImgSHA256)
		} else {
			p.Negative.add(*f.Vector, f.ImgSHA256)
		}
		// Explicit labels only; a rejected class never means safe content.
		region := collectRegionKey(f)
		if f.Vote == 1 && f.Adult != nil && rec.Sequence > ages[region].Sequence {
			ages[region] = rec
		}
	}
	ageKeys := make([]string, 0, len(ages))
	for key := range ages {
		ageKeys = append(ageKeys, key)
	}
	sort.Strings(ageKeys)
	for _, key := range ageKeys {
		f := ages[key].Feedback
		m.AgeSeen[key] = true
		if *f.Adult {
			m.Adult.add(*f.Vector, f.ImgSHA256)
		} else {
			m.Safe.add(*f.Vector, f.ImgSHA256)
		}
	}
	m.Samples = len(m.Records)
}

func (m *collectVectorModel) add(f collectFeedback) bool {
	if f.validate() != nil {
		return false
	}
	f.ImgSHA256 = strings.ToLower(f.ImgSHA256)
	key := collectSampleKey(f)
	old, exists := m.Records[key]
	if f.Vector == nil {
		if exists {
			delete(m.Records, key)
			m.rebuild()
		}
		return false
	}
	if exists && reflect.DeepEqual(old.Feedback, f) {
		return false
	}
	if !exists && len(m.Records) >= collectModelMaxSamples {
		m.Limited = true
		return false
	}
	if !exists && m.Classes[f.Box.Class] == nil && len(m.Classes) >= collectModelMaxClasses {
		m.Limited = true
		return false
	}
	// Own the values: callers may reuse or mutate their request buffers.
	vector := *f.Vector
	f.Vector = &vector
	if f.Adult != nil {
		adult := *f.Adult
		f.Adult = &adult
	}
	m.Sequence++
	m.Records[key] = collectRecord{Feedback: f, Sequence: m.Sequence}
	if exists || (f.Adult != nil && m.AgeSeen[collectRegionKey(f)]) {
		m.rebuild()
	} else {
		p := m.Classes[f.Box.Class]
		if p == nil {
			p = &collectClassModel{}
			m.Classes[f.Box.Class] = p
		}
		if f.Vote == 1 {
			p.Positive.add(*f.Vector, f.ImgSHA256)
		} else {
			p.Negative.add(*f.Vector, f.ImgSHA256)
		}
		m.Seen[key] = true
		m.Samples = len(m.Records)
		if f.Vote == 1 && f.Adult != nil {
			m.AgeSeen[collectRegionKey(f)] = true
			if *f.Adult {
				m.Adult.add(*f.Vector, f.ImgSHA256)
			} else {
				m.Safe.add(*f.Vector, f.ImgSHA256)
			}
		}
	}
	return true
}

// All cache access is serialized by collectMu. Disk is replayed as a stream once
// per changed file, with bounded deduplication and fixed-size prototypes.
var collectModelCache struct {
	Path     string
	Size     int64
	Modified time.Time
	Model    *collectVectorModel
}

func loadCollectModel(path string) (*collectVectorModel, error) {
	info, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	size := int64(0)
	if info != nil {
		size = info.Size()
	}
	modified := time.Time{}
	if info != nil {
		modified = info.ModTime()
	}
	if collectModelCache.Path == path && collectModelCache.Size == size && collectModelCache.Modified == modified && collectModelCache.Model != nil {
		return collectModelCache.Model, nil
	}
	m := newCollectVectorModel()
	if info != nil {
		fh, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 4096), 64<<10)
		for sc.Scan() {
			var f collectFeedback
			if json.Unmarshal(sc.Bytes(), &f) == nil {
				m.add(f)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	collectModelCache.Path = path
	collectModelCache.Size = size
	collectModelCache.Modified = modified
	collectModelCache.Model = m
	return m, nil
}

type collectPrediction struct {
	Class  string `json:"class,omitempty"`
	Score  int    `json:"score"`
	Age    string `json:"age"`
	Reason string `json:"reason"`
}

func (m *collectVectorModel) predict(v vision.VectorV1) collectPrediction {
	out := collectPrediction{Age: "unknown", Reason: "insufficient_labels"}
	best, second := math.Inf(1), math.Inf(1)
	readyClasses, correlatedLabels := 0, false
	for class, p := range m.Classes {
		if !p.Positive.ready() || !p.Negative.ready() {
			if p.Positive.N >= collectModelMinSamples && p.Negative.N >= collectModelMinSamples {
				correlatedLabels = true
			}
			continue
		}
		readyClasses++
		d, n := p.Positive.distance(v), p.Negative.distance(v)
		if d > 1.8 || n-d < .25 {
			continue
		}
		if d < best || (d == best && class < out.Class) {
			second = best
			best = d
			out.Class = class
		} else if d < second {
			second = d
		}
	}
	if out.Class == "" {
		if readyClasses > 0 {
			out.Reason = "no_supported_vector_match"
		} else if correlatedLabels {
			out.Reason = "insufficient_distinct_images"
		}
	}
	if out.Class != "" {
		if second-best < .2 {
			out.Class = ""
			out.Reason = "similar_classes"
		} else {
			out.Score = int(math.Round(100 * math.Exp(-best*best/2)))
			out.Reason = "vector_match"
		}
	}
	if m.Adult.ready() && m.Safe.ready() {
		a, s := m.Adult.distance(v), m.Safe.distance(v)
		if math.Min(a, s) <= 1.8 && math.Abs(a-s) >= .25 {
			out.Age = "safe"
			if a < s {
				out.Age = "adult"
			}
		}
	}
	return out
}

func serveCollectModel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	collectMu.Lock()
	defer collectMu.Unlock()
	m, err := loadCollectModel(collectFeedbackPath)
	if err != nil {
		collectJSONError(w, 500, err.Error())
		return
	}
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]any{"vector_version": vision.VectorVersion, "dimensions": 32, "samples": m.Samples, "max_samples": collectModelMaxSamples, "max_classes": collectModelMaxClasses, "min_samples": collectModelMinSamples, "min_images_per_label": collectModelMinSamples, "classes": m.Classes, "adult_samples": m.Adult.N, "safe_samples": m.Safe.N, "adult_images": m.Adult.Images, "safe_images": m.Safe.Images, "limited": m.Limited, "calibrated": false})
		return
	}
	var input struct {
		Vectors []vision.VectorV1 `json:"vectors"`
		Version int               `json:"vector_version"`
	}
	b, err := readCollectBody(w, r)
	if err != nil {
		collectJSONError(w, 413, err.Error())
		return
	}
	if err := strict(b, &input); err != nil {
		collectJSONError(w, 400, err.Error())
		return
	}
	if input.Version != vision.VectorVersion || len(input.Vectors) < 1 || len(input.Vectors) > 64 {
		collectJSONError(w, 400, "vector_version must be 1; vectors must contain 1..64 descriptors")
		return
	}
	out := make([]collectPrediction, len(input.Vectors))
	for i, v := range input.Vectors {
		out[i] = m.predict(v)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"predictions": out, "calibrated": false})
}
