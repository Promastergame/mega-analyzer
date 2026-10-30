package fusion

import (
	"errors"
	"math"
	"sort"

	"mega-analyzer/pkg/ml/anomaly"
)

// MemoryConfig configures the knowledge memory.
type MemoryConfig struct {
	Dims          int
	Planes        int
	Seed          int64
	ClusterCosine float64 // min cosine to join an existing cluster (default 0.85)
	TopK          int
}

// DefaultMemoryConfig returns defaults for a given feature width.
func DefaultMemoryConfig(dims int) MemoryConfig {
	return MemoryConfig{Dims: dims, Planes: 48, Seed: 1, ClusterCosine: 0.85, TopK: 5}
}

// Record is a remembered analysis: a feature vector plus a label (family,
// obfuscation technique, incident id, ...).
type Record struct {
	ID    string
	Label string
	Vec   []float64
}

// Cluster is an online-formed group of similar records.
type Cluster struct {
	ID       int            `json:"id"`
	Centroid []float64      `json:"-"`
	Count    int            `json:"count"`
	Labels   map[string]int `json:"labels"`
}

// LabelMatch aggregates similarity hits by label — "resembles family A: 87%".
type LabelMatch struct {
	Label      string  `json:"label"`
	Similarity float64 `json:"similarity"` // best cosine for that label [0,1]
	Hits       int     `json:"hits"`
}

// KnowledgeMemory is a CPU-friendly similarity + clustering memory built on
// the anomaly package's SimHash LSH index. It supports fast nearest-neighbour
// recall, online leader clustering, and label-aggregated resemblance.
type KnowledgeMemory struct {
	cfg      MemoryConfig
	index    *anomaly.LSHIndex
	records  map[string]Record
	order    []string
	clusters []*Cluster
}

// NewKnowledgeMemory builds an empty memory, normalising invalid config.
func NewKnowledgeMemory(cfg MemoryConfig) *KnowledgeMemory {
	if cfg.Dims <= 0 {
		cfg.Dims = 1
	}
	if cfg.Planes <= 0 {
		cfg.Planes = 48
	}
	if cfg.ClusterCosine <= 0 {
		cfg.ClusterCosine = 0.85
	}
	if cfg.TopK <= 0 {
		cfg.TopK = 5
	}
	return &KnowledgeMemory{
		cfg:     cfg,
		index:   anomaly.NewLSHIndex(cfg.Dims, cfg.Planes, cfg.Seed),
		records: make(map[string]Record),
	}
}

// Len returns the number of remembered records.
func (m *KnowledgeMemory) Len() int { return len(m.records) }

// Clusters returns the current cluster set.
func (m *KnowledgeMemory) Clusters() []*Cluster { return m.clusters }

// Remember stores a record: indexes it for similarity search and assigns it
// to an online cluster (leader clustering by cosine radius).
func (m *KnowledgeMemory) Remember(rec Record) error {
	if len(rec.Vec) != m.cfg.Dims {
		return errors.New("fusion: record width mismatch")
	}
	if rec.ID == "" {
		rec.ID = "rec_" + itoa(len(m.records))
	}
	cp := append([]float64(nil), rec.Vec...)
	rec.Vec = cp
	if _, exists := m.records[rec.ID]; !exists {
		m.order = append(m.order, rec.ID)
	}
	m.records[rec.ID] = rec
	if err := m.index.Add(rec.ID, cp); err != nil {
		return err
	}
	m.assignCluster(rec)
	return nil
}

func (m *KnowledgeMemory) assignCluster(rec Record) {
	best := -1
	bestCos := -1.0
	for i, c := range m.clusters {
		cos := cosine(rec.Vec, c.Centroid)
		if cos > bestCos {
			bestCos = cos
			best = i
		}
	}
	if best >= 0 && bestCos >= m.cfg.ClusterCosine {
		c := m.clusters[best]
		for j := range c.Centroid {
			c.Centroid[j] += (rec.Vec[j] - c.Centroid[j]) / float64(c.Count+1)
		}
		c.Count++
		if rec.Label != "" {
			c.Labels[rec.Label]++
		}
		return
	}
	nc := &Cluster{
		ID:       len(m.clusters),
		Centroid: append([]float64(nil), rec.Vec...),
		Count:    1,
		Labels:   map[string]int{},
	}
	if rec.Label != "" {
		nc.Labels[rec.Label]++
	}
	m.clusters = append(m.clusters, nc)
}

// Similar returns the k nearest remembered records to vec.
func (m *KnowledgeMemory) Similar(vec []float64, k int) ([]anomaly.Neighbor, error) {
	if k <= 0 {
		k = m.cfg.TopK
	}
	return m.index.Query(vec, k)
}

// Resembles aggregates nearest neighbours by label to answer "what does this
// look like?" — returning the best cosine per label, sorted descending.
func (m *KnowledgeMemory) Resembles(vec []float64, k int) ([]LabelMatch, error) {
	if k <= 0 {
		k = m.cfg.TopK * 4
	}
	neigh, err := m.index.Query(vec, k)
	if err != nil {
		return nil, err
	}
	byLabel := map[string]*LabelMatch{}
	for _, n := range neigh {
		rec, ok := m.records[n.ID]
		if !ok || rec.Label == "" {
			continue
		}
		sim := n.Cosine
		if sim < 0 {
			sim = 0
		}
		if lm, ok := byLabel[rec.Label]; ok {
			lm.Hits++
			if sim > lm.Similarity {
				lm.Similarity = sim
			}
		} else {
			byLabel[rec.Label] = &LabelMatch{Label: rec.Label, Similarity: sim, Hits: 1}
		}
	}
	out := make([]LabelMatch, 0, len(byLabel))
	for _, lm := range byLabel {
		out = append(out, *lm)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Similarity != out[j].Similarity {
			return out[i].Similarity > out[j].Similarity
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > m.cfg.TopK {
		out = out[:m.cfg.TopK]
	}
	return out, nil
}

func cosine(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
