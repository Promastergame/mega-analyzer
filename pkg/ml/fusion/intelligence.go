package fusion

import (
	"sync"

	"mega-analyzer/pkg/ml/anomaly"
)

// ScoreProvider is any supervised model that yields a probability in [0,1].
// The existing GBT / logistic / multiclass / HDC models satisfy this with a
// thin adapter, so the intelligence layer stays decoupled from concrete model
// types and never imports the heavy pkg/ml root (avoiding an import cycle).
type ScoreProvider interface {
	Name() string
	Weight() float64
	Score(x []float64) float64
}

// Sample is one unit of analysis presented to the intelligence engine.
type Sample struct {
	ID       string
	Features []float64
	// Extra lets callers attach discrete, human-readable detections
	// (e.g. "CFG flattening detected") that appear in the evidence list.
	Extra []Evidence
}

// Report is the full, explainable output of the intelligence engine.
type Report struct {
	SampleID    string             `json:"sample_id"`
	Decision    Decision           `json:"decision"`
	Anomaly     float64            `json:"anomaly_score"`
	Resembles   []LabelMatch       `json:"resembles,omitempty"`
	Neighbors   []anomaly.Neighbor `json:"neighbors,omitempty"`
	TopFeatures []FeatureScore     `json:"top_features,omitempty"`
}

// IntelligenceConfig wires the whole engine together.
type IntelligenceConfig struct {
	Schema   []string
	Fusion   FusionConfig
	Memory   MemoryConfig
	Detector anomaly.Config

	// Weights for the built-in intrinsic signals.
	AnomalyWeight    float64
	SimilarityWeight float64
	OnlineWeight     float64

	// OnlineLR and OnlineL2 tune the incremental learner.
	OnlineLR float64
	OnlineL2 float64
}

// Intelligence is the central decision layer: it fuses supervised providers,
// an unsupervised anomaly detector, an online-learned model, and a similarity
// memory into a single explainable Report, and learns incrementally from
// feedback. Designed to run comfortably on 4-core, CUDA-free hardware.
type Intelligence struct {
	mu        sync.RWMutex // guards all mutable fields below
	cfg       IntelligenceConfig
	fusion    *FusionEngine
	detector  *anomaly.Detector
	online    *OnlineLogistic
	memory    *KnowledgeMemory
	monitor   *FeatureMonitor
	providers []ScoreProvider
	dims      int
}

// NewIntelligence builds the engine. Additional supervised ScoreProviders
// (GBM, HDC, ...) can be supplied; the engine also maintains its own online
// model, anomaly detector and similarity memory.
func NewIntelligence(cfg IntelligenceConfig, providers ...ScoreProvider) *Intelligence {
	dims := len(cfg.Schema)
	if cfg.AnomalyWeight <= 0 {
		cfg.AnomalyWeight = 1.0
	}
	if cfg.SimilarityWeight <= 0 {
		cfg.SimilarityWeight = 0.8
	}
	if cfg.OnlineWeight <= 0 {
		cfg.OnlineWeight = 1.0
	}
	if cfg.OnlineLR <= 0 {
		cfg.OnlineLR = 0.1
	}
	if cfg.OnlineL2 < 0 {
		cfg.OnlineL2 = 0
	}
	if cfg.Memory.Dims == 0 {
		cfg.Memory = DefaultMemoryConfig(dims)
	}
	return &Intelligence{
		cfg:       cfg,
		fusion:    NewFusionEngine(cfg.Fusion),
		online:    NewOnlineLogistic(dims, cfg.OnlineLR, cfg.OnlineL2),
		memory:    NewKnowledgeMemory(cfg.Memory),
		monitor:   NewFeatureMonitor(cfg.Schema, 1024),
		providers: providers,
		dims:      dims,
	}
}

// FitDetector trains the unsupervised anomaly detector on a background
// corpus. Optional: until trained, the engine simply omits the anomaly
// signal from fusion.
func (in *Intelligence) FitDetector(corpus [][]float64, ids []string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	d := anomaly.NewDetector(in.cfg.Schema, in.cfg.Detector)
	if err := d.Fit(corpus, ids); err != nil {
		return err
	}
	in.detector = d
	return nil
}

// Analyze produces a full, explainable Report for one sample by fusing every
// available signal.
func (in *Intelligence) Analyze(s Sample) (Report, error) {
	in.mu.RLock()
	defer in.mu.RUnlock()
	rep := Report{SampleID: s.ID}
	signals := make([]ModelSignal, 0, len(in.providers)+3)

	// Supervised providers (GBM, HDC, ...).
	for _, p := range in.providers {
		signals = append(signals, ModelSignal{Name: p.Name(), Score: p.Score(s.Features), Weight: p.Weight()})
	}

	// Online-learned model (only once it has seen data).
	if in.online.Samples() > 0 {
		signals = append(signals, ModelSignal{
			Name:   "online",
			Score:  in.online.PredictProba(s.Features),
			Weight: in.cfg.OnlineWeight,
		})
	}

	// Unsupervised anomaly.
	if in.detector != nil {
		if res, err := in.detector.Analyze(s.Features); err == nil {
			rep.Anomaly = res.Score
			signals = append(signals, ModelSignal{Name: "anomaly", Score: res.Score, Weight: in.cfg.AnomalyWeight})
		}
	}

	// Similarity / historical knowledge.
	if in.memory.Len() > 0 {
		if resembles, err := in.memory.Resembles(s.Features, in.cfg.Memory.TopK); err == nil && len(resembles) > 0 {
			rep.Resembles = resembles
			signals = append(signals, ModelSignal{Name: "similarity", Score: resembles[0].Similarity, Weight: in.cfg.SimilarityWeight})
		}
		if neigh, err := in.memory.Similar(s.Features, in.cfg.Memory.TopK); err == nil {
			rep.Neighbors = neigh
		}
	}

	rep.Decision = in.fusion.Fuse(signals, s.Extra)

	// Attach top feature intelligence for explainability.
	fs := in.monitor.Scores()
	if len(fs) > 5 {
		fs = fs[:5]
	}
	rep.TopFeatures = fs
	return rep, nil
}

// Learn folds a labelled sample into the continuous-learning loop: online
// model update, feature-intelligence update, and (when a label/id is present)
// the similarity memory. No full retraining is performed.
func (in *Intelligence) Learn(s Sample, label int, memoryLabel string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if _, err := in.online.Update(s.Features, label); err != nil {
		return err
	}
	if err := in.monitor.Observe(s.Features, label); err != nil {
		return err
	}
	if memoryLabel != "" || s.ID != "" {
		if err := in.memory.Remember(Record{ID: s.ID, Label: memoryLabel, Vec: s.Features}); err != nil {
			return err
		}
	}
	return nil
}

// FeatureReport exposes current feature intelligence (importance, drift,
// uselessness) for dashboards and pruning decisions.
func (in *Intelligence) FeatureReport() []FeatureScore { return in.monitor.Scores() }

// AdaptiveWeights returns the learned per-feature weights.
func (in *Intelligence) AdaptiveWeights() []float64 { return in.monitor.AdaptiveWeights() }

// Memory exposes the knowledge memory for direct clustering/similarity use.
func (in *Intelligence) Memory() *KnowledgeMemory { return in.memory }

// OnlineSamples reports how many feedback samples the online model has seen.
func (in *Intelligence) OnlineSamples() int { return in.online.Samples() }
