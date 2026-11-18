// Package contentcache — Pipeline Integration Layer
//
// Provides high-level API for integrating content-addressed caching
// into the analysis pipeline. Wraps Store with method-level operations.
package contentcache

import (
	"encoding/json"
	"strings"
	"sync/atomic"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PIPELINE CACHE — High-level API for method analysis caching
// ═══════════════════════════════════════════════════════════════════════════════

// PipelineCache wraps Store with method-analysis-specific operations.
type PipelineCache struct {
	store *Store

	// Stats
	methodHits   atomic.Int64
	methodMisses atomic.Int64
	methodStores atomic.Int64
	bytesReused  atomic.Int64
}

// NewPipelineCache creates a pipeline cache with the given store.
func NewPipelineCache(store *Store) *PipelineCache {
	return &PipelineCache{store: store}
}

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD-LEVEL OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// CachedMethodMetrics represents cached metrics for a method.
type CachedMethodMetrics struct {
	Cyclomatic     int     `json:"cyclomatic"`
	Nesting        int     `json:"nesting"`
	Cognitive      int     `json:"cognitive"`
	LOC            int     `json:"loc"`
	Halstead       float64 `json:"halstead"`
	SuspicionScore float64 `json:"suspicion_score"`
}

// CachedFeatures represents cached feature extraction results.
type CachedFeatures struct {
	FeatureIDs    []string `json:"feature_ids"`
	WeightedScore float64  `json:"weighted_score"`
	RiskLevel     int      `json:"risk_level"`
	SynergyBonus  float64  `json:"synergy_bonus"`
}

// CachedCFGSummary represents a cached CFG summary (not the full graph).
type CachedCFGSummary struct {
	NodeCount       int  `json:"node_count"`
	EdgeCount       int  `json:"edge_count"`
	HasLoops        bool `json:"has_loops"`
	HasExceptions   bool `json:"has_exceptions"`
	MaxNesting      int  `json:"max_nesting"`
	CyclomaticCompl int  `json:"cyclomatic"`
	IsReducible     bool `json:"is_reducible"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// GetMetrics retrieves cached metrics for a method body.
func (pc *PipelineCache) GetMetrics(body []string) (*CachedMethodMetrics, bool) {
	key := ComputeKeyFromBody(body)
	result, ok := GetJSON[CachedMethodMetrics](pc.store, NamespaceMetrics, key)
	if ok {
		pc.methodHits.Add(1)
	} else {
		pc.methodMisses.Add(1)
	}
	return result, ok
}

// GetFeatures retrieves cached features for a method body.
func (pc *PipelineCache) GetFeatures(body []string) (*CachedFeatures, bool) {
	key := ComputeKeyFromBody(body)
	result, ok := GetJSON[CachedFeatures](pc.store, NamespaceFeatures, key)
	if ok {
		pc.methodHits.Add(1)
	} else {
		pc.methodMisses.Add(1)
	}
	return result, ok
}

// GetMethodFeatures retrieves cached features using both the method identity
// and normalized body. Body-only keys can incorrectly reuse class/name based
// features (for example name_contains_check) across unrelated methods.
func (pc *PipelineCache) GetMethodFeatures(className, methodName, params string, body []string) (*CachedFeatures, bool) {
	key := ComputeMethodKey(className, methodName, params, body)
	result, ok := GetJSON[CachedFeatures](pc.store, NamespaceFeatures, key)
	if ok {
		pc.methodHits.Add(1)
	} else {
		pc.methodMisses.Add(1)
	}
	return result, ok
}

// GetCFGSummary retrieves cached CFG summary for a method body.
func (pc *PipelineCache) GetCFGSummary(body []string) (*CachedCFGSummary, bool) {
	key := ComputeKeyFromBody(body)
	result, ok := GetJSON[CachedCFGSummary](pc.store, NamespaceCFG, key)
	if ok {
		pc.methodHits.Add(1)
	} else {
		pc.methodMisses.Add(1)
	}
	return result, ok
}

// GetRawCFG retrieves the full serialized CFG (for methods that need deep analysis).
func (pc *PipelineCache) GetRawCFG(body []string) ([]byte, bool) {
	key := ComputeKeyFromBody(body)
	data, ok := pc.store.Get(NamespaceCFG, key)
	if ok {
		pc.methodHits.Add(1)
		pc.bytesReused.Add(int64(len(data)))
	} else {
		pc.methodMisses.Add(1)
	}
	return data, ok
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUT OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// PutMetrics stores metrics for a method body.
func (pc *PipelineCache) PutMetrics(body []string, metrics *CachedMethodMetrics) {
	key := ComputeKeyFromBody(body)
	_ = PutJSON(pc.store, NamespaceMetrics, key, metrics)
	pc.methodStores.Add(1)
}

// PutFeatures stores features for a method body.
func (pc *PipelineCache) PutFeatures(body []string, features *CachedFeatures) {
	key := ComputeKeyFromBody(body)
	_ = PutJSON(pc.store, NamespaceFeatures, key, features)
	pc.methodStores.Add(1)
}

// PutMethodFeatures stores features under a context-aware method key.
func (pc *PipelineCache) PutMethodFeatures(className, methodName, params string, body []string, features *CachedFeatures) {
	key := ComputeMethodKey(className, methodName, params, body)
	if err := PutJSON(pc.store, NamespaceFeatures, key, features); err == nil {
		pc.methodStores.Add(1)
	}
}

// PutCFGSummary stores a CFG summary for a method body.
func (pc *PipelineCache) PutCFGSummary(body []string, summary *CachedCFGSummary) {
	key := ComputeKeyFromBody(body)
	_ = PutJSON(pc.store, NamespaceCFG, key, summary)
	pc.methodStores.Add(1)
}

// PutRawCFG stores the full serialized CFG.
func (pc *PipelineCache) PutRawCFG(body []string, data []byte) {
	key := ComputeKeyFromBody(body)
	_ = pc.store.Put(NamespaceCFG, key, data)
	pc.methodStores.Add(1)
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH OPERATIONS — for incremental analysis
// ═══════════════════════════════════════════════════════════════════════════════

// BatchLookup checks which methods already have cached results.
// Returns a map of method signature → bool (true = cached).
func (pc *PipelineCache) BatchLookup(methods []MethodInput, ns Namespace) map[string]bool {
	result := make(map[string]bool, len(methods))
	for _, m := range methods {
		key := ComputeKeyFromBody(m.Body)
		result[m.FullSignature] = pc.store.Has(ns, key)
	}
	return result
}

// BatchGetFeatures retrieves features for multiple methods at once.
// Returns only the ones that are cached.
func (pc *PipelineCache) BatchGetFeatures(methods []MethodInput) map[string]*CachedFeatures {
	result := make(map[string]*CachedFeatures)
	for _, m := range methods {
		key := ComputeKeyFromBody(m.Body)
		if features, ok := GetJSON[CachedFeatures](pc.store, NamespaceFeatures, key); ok {
			result[m.FullSignature] = features
			pc.methodHits.Add(1)
		} else {
			pc.methodMisses.Add(1)
		}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEOBFUSCATION CACHE
// ═══════════════════════════════════════════════════════════════════════════════

// CachedDeobfResult represents cached deobfuscation output.
type CachedDeobfResult struct {
	DeobfuscatedBody []string `json:"deobf_body"`
	CFFFDetected     bool     `json:"cff_detected,omitempty"`
	Findings         []string `json:"findings,omitempty"`
	ConstantsProp    int      `json:"constants_propagated"`
	DeadCodeRemoved  int      `json:"dead_code_removed"`
	OpaqueRemoved    int      `json:"opaque_removed"`
	Confidence       float64  `json:"confidence"`
}

// GetDeobf retrieves cached deobfuscation result.
func (pc *PipelineCache) GetDeobf(body []string) (*CachedDeobfResult, bool) {
	key := ComputeKeyFromBody(body)
	return GetJSON[CachedDeobfResult](pc.store, NamespaceDeobf, key)
}

// PutDeobf stores deobfuscation result.
func (pc *PipelineCache) PutDeobf(body []string, result *CachedDeobfResult) {
	key := ComputeKeyFromBody(body)
	_ = PutJSON(pc.store, NamespaceDeobf, key, result)
}

// Method deobfuscation uses a separate, versioned key from the legacy body-only
// cache. Options and identity are inputs to the analysis, including negative
// results; old entries lack structural findings and must not be reused.
func deobfMethodKey(className, methodName, signature, options string, body []string) ContentKey {
	input := make([]string, 0, len(body)+2)
	// v4 recovers salted nibble strings and rejects raw transforms of opaque
	// encoded blobs; older positive and negative results are stale.
	input = append(input, "deobfuscation-v4", options)
	input = append(input, body...)
	return ComputeMethodKey(className, methodName, signature, input)
}

func (pc *PipelineCache) GetMethodDeobf(className, methodName, signature, options string, body []string) (*CachedDeobfResult, bool) {
	key := deobfMethodKey(className, methodName, signature, options, body)
	return GetJSON[CachedDeobfResult](pc.store, NamespaceDeobf, key)
}

func (pc *PipelineCache) PutMethodDeobf(className, methodName, signature, options string, body []string, result *CachedDeobfResult) {
	key := deobfMethodKey(className, methodName, signature, options, body)
	_ = PutJSON(pc.store, NamespaceDeobf, key, result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAINT CACHE
// ═══════════════════════════════════════════════════════════════════════════════

// CachedTaintSummary represents cached taint analysis summary for a method.
type CachedTaintSummary struct {
	ParamToReturn map[int]bool      `json:"param_to_return"`
	IsSource      bool              `json:"is_source"`
	IsSink        bool              `json:"is_sink"`
	TaintedRegs   map[string]uint64 `json:"tainted_regs"` // reg → TaintLabel
}

// GetTaintSummary retrieves cached taint summary.
func (pc *PipelineCache) GetTaintSummary(body []string) (*CachedTaintSummary, bool) {
	key := ComputeKeyFromBody(body)
	return GetJSON[CachedTaintSummary](pc.store, NamespaceTaint, key)
}

// PutTaintSummary stores taint summary.
func (pc *PipelineCache) PutTaintSummary(body []string, summary *CachedTaintSummary) {
	key := ComputeKeyFromBody(body)
	_ = PutJSON(pc.store, NamespaceTaint, key, summary)
}

// GetMethodTaintData exposes raw summary bytes without coupling contentcache
// to the data-flow engine's concrete summary type.
func (pc *PipelineCache) GetMethodTaintData(signature string, body []string) ([]byte, bool) {
	key := ComputeMethodKey("", signature, "", body)
	data, ok := pc.store.Get(NamespaceTaint, key)
	if ok {
		pc.methodHits.Add(1)
		pc.bytesReused.Add(int64(len(data)))
	} else {
		pc.methodMisses.Add(1)
	}
	return data, ok
}

func (pc *PipelineCache) PutMethodTaintData(signature string, body []string, data []byte) {
	key := ComputeMethodKey("", signature, "", body)
	if err := pc.store.Put(NamespaceTaint, key, data); err == nil {
		pc.methodStores.Add(1)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════

// PipelineCacheStats returns pipeline-level cache statistics.
type PipelineCacheStats struct {
	MethodHits   int64   `json:"method_hits"`
	MethodMisses int64   `json:"method_misses"`
	MethodStores int64   `json:"method_stores"`
	HitRate      float64 `json:"hit_rate"`
	BytesReused  int64   `json:"bytes_reused"`
	StoreStats   Stats   `json:"store_stats"`
}

func (pc *PipelineCache) Stats() PipelineCacheStats {
	hits := pc.methodHits.Load()
	misses := pc.methodMisses.Load()
	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return PipelineCacheStats{
		MethodHits:   hits,
		MethodMisses: misses,
		MethodStores: pc.methodStores.Load(),
		HitRate:      hitRate,
		BytesReused:  pc.bytesReused.Load(),
		StoreStats:   pc.store.Stats(),
	}
}

// ResetStats starts a new per-scan measurement window without discarding hot
// entries. Pipeline runs are serialized, so resetting is race-free there.
func (pc *PipelineCache) ResetStats() {
	pc.methodHits.Store(0)
	pc.methodMisses.Store(0)
	pc.methodStores.Store(0)
	pc.bytesReused.Store(0)
	pc.store.ResetStats()
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY COMPUTATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// ComputeMethodKey computes a content key from method signature + body.
// Use this when you need a key that includes the method context.
func ComputeMethodKey(className, methodName, params string, body []string) ContentKey {
	// Combine signature with body for a unique key
	var combined []string
	combined = append(combined, className+"->"+methodName+"("+params+")")
	combined = append(combined, body...)
	return ComputeKeyFromBody(combined)
}

// ComputeClassKey computes a content key for an entire class.
func ComputeClassKey(className string, methodBodies [][]string) ContentKey {
	var allLines []string
	allLines = append(allLines, className)
	for _, body := range methodBodies {
		allLines = append(allLines, body...)
		allLines = append(allLines, "---") // separator
	}
	return ComputeKeyFromBody(allLines)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERIALIZATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// MarshalCompact marshals to compact JSON (no indentation).
func MarshalCompact(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// BodyFingerprint returns a short fingerprint of a method body for logging.
func BodyFingerprint(body []string) string {
	key := ComputeKeyFromBody(body)
	lines := 0
	for _, l := range body {
		if strings.TrimSpace(l) != "" {
			lines++
		}
	}
	return key.Short() + ":" + string(rune('0'+lines/10)) + string(rune('0'+lines%10))
}
