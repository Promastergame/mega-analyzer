// Package gnncache provides a persistent, content-addressed cache for GNN
// vulnerability-classification results.
//
// Cache keys are derived from the full graph tensor (CSR structure plus node
// features) and a fingerprint of the model weight file, so any change to
// either the graph or the model automatically invalidates the entry.
//
// Dummy models ("__dummy__") are Xavier-initialized with random weights on
// every load; their predictions are not reproducible and are never cached.
package gnncache

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/contentcache"
)

// DummyModelPath is the sentinel weight path for a randomly initialized model.
const DummyModelPath = "__dummy__"

// inferenceSchemaVersion changes whenever graph preprocessing, Rust inference
// semantics, or the cache-key derivation change. It prevents old predictions
// (for example from the formerly corrupted FFI self-loop CSR) from surviving
// an analyzer update.
//
// Version 4: keys are derived from a single TensorDigest, and hashTensor
// packs edge types and features as 4-byte values.
//
// Version 5: keys additionally bind the normalized smali method body. Two
// different methods with identical CFG topology and identical normalized node
// features previously produced the same TensorDigest, hence the same key, and
// silently reused each other's prediction. For a security classifier that is
// a false or lost finding, not a harmless cache miss.
//
// Version 6: node feature 16 now counts typed operands instead of commas in
// the raw instruction text, so the same method produces a different tensor
// than under version 5. Predictions computed from the old feature layout must
// not be served for the new one.
//
// Version 7: 8 semantic API/string slots appended (28 -> 36 dims,
// "smali-cfg-v3"), so every tensor — and therefore every prediction —
// differs from version 6 by construction.
const inferenceSchemaVersion uint64 = 7

const (
	cacheRecordVersion = uint32(1)
	gnnClassCount      = 8
)

// ErrDummyModel is returned by Open when caching is requested for a dummy model.
var ErrDummyModel = errors.New("gnncache: dummy models are randomly initialized; results are not cacheable")

// ErrInvalidFingerprint is returned when Open receives anything other than a
// SHA-256 model fingerprint. Accepting arbitrary strings here makes accidental
// model/cache aliasing much easier and weakens the cache-key contract.
var ErrInvalidFingerprint = errors.New("gnncache: model fingerprint must be a 64-character SHA-256 hex digest")

// ErrInvalidPrediction is returned when an inference result is not a finite,
// normalized eight-class probability distribution whose argmax agrees with
// PredictedClass and Confidence.
var ErrInvalidPrediction = errors.New("gnncache: invalid prediction")

// ErrComputeAborted is shared with waiters if the goroutine responsible for
// an inference exits without returning (for example via runtime.Goexit).
var ErrComputeAborted = errors.New("gnncache: inference computation aborted")

// ModelFingerprint returns a stable fingerprint (SHA-256 hex) of the model
// weight file. It returns "" without an error for dummy models (an empty path
// or DummyModelPath), because their weights differ on every load.
func ModelFingerprint(path string) (string, error) {
	if path == "" || path == DummyModelPath {
		return "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("gnncache: model weights are not a regular file: %s", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Prediction is the cached result of a single GNN inference.
type Prediction struct {
	PredictedClass int       `json:"class"`
	Confidence     float32   `json:"confidence"`
	ClassProbs     []float32 `json:"probs,omitempty"`
}

// GraphTensor mirrors the CSR graph representation passed to the GNN.
type GraphTensor struct {
	RowPtrs    []uint64
	ColIndices []uint64
	EdgeTypes  []uint32
	Features   []float32
	NumNodes   uint64
	FeatureDim uint64
}

// Cache is a persistent GNN prediction cache backed by the shared
// content-addressed store (in-memory hot cache plus disk).
type Cache struct {
	store       *contentcache.Store
	fingerprint []byte
	rejected    atomic.Int64

	// Rejection reasons, split so cache corruption is diagnosable from a log
	// line instead of a single opaque counter.
	rejectedMalformed atomic.Int64
	rejectedSchema    atomic.Int64
	rejectedKey       atomic.Int64
	rejectedInvalid   atomic.Int64
	rejectedIntegrity atomic.Int64
}

// RejectionStats breaks RejectedEntries down by cause.
type RejectionStats struct {
	Total     int64 `json:"total"`
	Malformed int64 `json:"malformed"`
	Schema    int64 `json:"schema"`
	Key       int64 `json:"key_mismatch"`
	Invalid   int64 `json:"invalid_prediction"`
	Integrity int64 `json:"integrity_mismatch"`
}

// rejectReason enumerates why a stored record was discarded.
type rejectReason int

const (
	reasonOK rejectReason = iota
	reasonMalformed
	reasonSchema
	reasonKeyMismatch
	reasonInvalidPrediction
	reasonIntegrityMismatch
)

type cacheRecord struct {
	Version    uint32     `json:"version"`
	Key        string     `json:"key"`
	Prediction Prediction `json:"prediction"`
	Integrity  string     `json:"integrity"`
}

// Open creates a GNN cache under baseDir. modelFingerprint must be non-empty
// (see ModelFingerprint); dummy models are rejected with ErrDummyModel.
// maxDiskBytes of 0 means unlimited disk usage.
func Open(baseDir string, maxDiskBytes int64, modelFingerprint string) (*Cache, error) {
	if modelFingerprint == "" {
		return nil, ErrDummyModel
	}
	if maxDiskBytes < 0 {
		return nil, fmt.Errorf("gnncache: negative disk limit: %d", maxDiskBytes)
	}
	if len(modelFingerprint) != sha256.Size*2 {
		return nil, ErrInvalidFingerprint
	}
	fp, err := hex.DecodeString(modelFingerprint)
	if err != nil || len(fp) != sha256.Size {
		return nil, ErrInvalidFingerprint
	}
	cfg := contentcache.DefaultStoreConfig()
	if baseDir != "" {
		cfg.BaseDir = baseDir
	}
	cfg.MaxDiskBytes = maxDiskBytes
	store, err := contentcache.NewStore(cfg)
	if err != nil {
		return nil, err
	}
	return &Cache{store: store, fingerprint: fp}, nil
}

// TensorDigest hashes the full graph tensor exactly once. Both the run-local
// memo key (GraphKeyFromDigest) and the persistent cache key (KeyFromDigest)
// are derived from this digest, so callers needing both keys traverse the
// CSR + feature tensor with SHA-256 a single time instead of twice.
func TensorDigest(g *GraphTensor) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("omnisec/gnn/tensor-digest\x00"))
	hashTensor(h, g)
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// GraphContext is everything a cache key is derived from: the graph tensor
// digest plus, when available, the normalized smali method body.
//
// The tensor alone is not a safe identity. gnngraph.Builder.Build derives it
// purely from CFG topology and normalized node features, so two genuinely
// different methods that share a shape collide. Binding the body makes the
// key identify the method, not just its silhouette.
type GraphContext struct {
	TensorDigest [sha256.Size]byte
	BodyKey      contentcache.ContentKey
	HasBody      bool
}

// NewGraphContext builds a body-bound context. Use contentcache.ComputeKeyFromBody
// (the same normalizer the incremental cache uses) to produce bodyKey.
func NewGraphContext(digest [sha256.Size]byte, bodyKey contentcache.ContentKey) GraphContext {
	return GraphContext{TensorDigest: digest, BodyKey: bodyKey, HasBody: true}
}

// ContextFromBody builds a graph context directly from smali body lines.
// An empty body yields HasBody=false, matching the legacy key derivation.
func ContextFromBody(digest [sha256.Size]byte, body []string) GraphContext {
	if len(body) == 0 {
		return GraphContext{TensorDigest: digest}
	}
	bodyKey := contentcache.ComputeKeyFromBody(body)
	if bodyKey == emptyBodyKey() {
		// Blank lines and comments only: the normalizer saw nothing, so this
		// is indistinguishable from a missing body and must not be treated
		// as a distinguishing key component.
		return GraphContext{TensorDigest: digest}
	}
	return NewGraphContext(digest, bodyKey)
}

// emptyBodyKey is the key the shared normalizer produces for a body with no
// significant lines. Computed from the normalizer itself so the two can never
// drift apart.
var emptyBodyKey = sync.OnceValue(func() contentcache.ContentKey {
	return contentcache.ComputeKeyFromBody(nil)
})

// writeContext serializes a context into h with an explicit presence flag and
// a length prefix, so a body-bound context can never collide with a bodyless
// one by concatenation.
func writeContext(h hash.Hash, ctx GraphContext) {
	h.Write(ctx.TensorDigest[:])
	var hdr [9]byte
	if ctx.HasBody {
		hdr[0] = 1
		binary.LittleEndian.PutUint64(hdr[1:], uint64(len(ctx.BodyKey)))
		h.Write(hdr[:])
		h.Write(ctx.BodyKey[:])
		return
	}
	h.Write(hdr[:])
}

// Key derives the content key for a graph tensor under this cache's model.
func (c *Cache) Key(g *GraphTensor) contentcache.ContentKey {
	return c.KeyFromDigest(TensorDigest(g))
}

// KeyFromDigest derives the cache key from a precomputed TensorDigest
// without re-hashing the tensor. It is the bodyless (legacy) derivation and
// remains available for callers with no smali source.
func (c *Cache) KeyFromDigest(digest [sha256.Size]byte) contentcache.ContentKey {
	return c.KeyFromContext(GraphContext{TensorDigest: digest})
}

// KeyFromContext derives the persistent cache key from a graph context.
func (c *Cache) KeyFromContext(ctx GraphContext) contentcache.ContentKey {
	h := sha256.New()
	h.Write([]byte("omnisec/gnn/prediction-key\x01"))
	var version [8]byte
	binary.LittleEndian.PutUint64(version[:], inferenceSchemaVersion)
	h.Write(version[:])
	h.Write(c.fingerprint)
	writeContext(h, ctx)
	var key contentcache.ContentKey
	copy(key[:], h.Sum(nil))
	return key
}

// GraphKey hashes the tensor alone, without any model fingerprint. It is
// meant for run-local deduplication of identical graphs and works for dummy
// models too, because it does not depend on the weights.
func GraphKey(g *GraphTensor) contentcache.ContentKey {
	return GraphKeyFromDigest(TensorDigest(g))
}

// GraphKeyFromDigest derives the run-local memo key from a precomputed
// TensorDigest without re-hashing the tensor.
func GraphKeyFromDigest(digest [sha256.Size]byte) contentcache.ContentKey {
	return GraphKeyFromContext(GraphContext{TensorDigest: digest})
}

// GraphKeyFromContext derives the run-local memo key from a graph context.
// The body is included here too: leaving it out would only move a tensor
// collision from the disk cache into the in-process memo table.
func GraphKeyFromContext(ctx GraphContext) contentcache.ContentKey {
	h := sha256.New()
	h.Write([]byte("omnisec/gnn/graph-key\x01"))
	writeContext(h, ctx)
	var key contentcache.ContentKey
	copy(key[:], h.Sum(nil))
	return key
}

// hashTensor writes every tensor field into h with length prefixes, so
// different tensors cannot collide by concatenation. Values are staged in a
// local buffer and flushed in ~8 KB chunks: one h.Write per chunk instead of
// one per element, which is a large win on feature-heavy graphs.
func hashTensor(h hash.Hash, g *GraphTensor) {
	if g == nil {
		h.Write([]byte{0})
		return
	}
	h.Write([]byte{1})
	buf := make([]byte, 0, 8192)
	flush := func() {
		if len(buf) > 0 {
			h.Write(buf)
			buf = buf[:0]
		}
	}
	writeU64 := func(v uint64) {
		if len(buf)+8 > cap(buf) {
			flush()
		}
		buf = binary.LittleEndian.AppendUint64(buf, v)
	}
	writeU32 := func(v uint32) {
		if len(buf)+4 > cap(buf) {
			flush()
		}
		buf = binary.LittleEndian.AppendUint32(buf, v)
	}
	writeU64(g.NumNodes)
	writeU64(g.FeatureDim)
	writeU64(uint64(len(g.RowPtrs)))
	for _, v := range g.RowPtrs {
		writeU64(v)
	}
	writeU64(uint64(len(g.ColIndices)))
	for _, v := range g.ColIndices {
		writeU64(v)
	}
	writeU64(uint64(len(g.EdgeTypes)))
	for _, v := range g.EdgeTypes {
		writeU32(v)
	}
	writeU64(uint64(len(g.Features)))
	for _, f := range g.Features {
		writeU32(math.Float32bits(f))
	}
	flush()
}

// Get returns a cached prediction for the key, if present.
func (c *Cache) Get(key contentcache.ContentKey) (*Prediction, bool) {
	data, ok := c.store.Get(contentcache.NamespaceGNN, key)
	if !ok {
		return nil, false
	}
	var record cacheRecord
	reason := reasonOK
	if err := json.Unmarshal(data, &record); err != nil {
		reason = reasonMalformed
	} else {
		reason = c.recordRejection(key, &record)
	}
	if reason != reasonOK {
		// A cache entry is untrusted input. Remove malformed, stale, swapped or
		// corrupted records so the caller recomputes a clean prediction instead
		// of turning cache damage into a missing/false security finding.
		c.store.Delete(contentcache.NamespaceGNN, key)
		c.noteRejection(reason)
		return nil, false
	}
	pred := record.Prediction
	pred.ClassProbs = append([]float32(nil), pred.ClassProbs...)
	return &pred, true
}

// Put stores a prediction for the key.
func (c *Cache) Put(key contentcache.ContentKey, pred *Prediction) error {
	if err := validatePrediction(pred); err != nil {
		return err
	}
	stored := *pred
	stored.ClassProbs = append([]float32(nil), pred.ClassProbs...)
	record := cacheRecord{
		Version:    cacheRecordVersion,
		Key:        key.Hex(),
		Prediction: stored,
	}
	record.Integrity = c.predictionIntegrity(key, &record.Prediction)
	data, err := json.Marshal(&record)
	if err != nil {
		return fmt.Errorf("gnncache: marshal prediction: %w", err)
	}
	return c.store.Put(contentcache.NamespaceGNN, key, data)
}

// recordRejection classifies a decoded record. reasonOK means it is usable.
func (c *Cache) recordRejection(key contentcache.ContentKey, record *cacheRecord) rejectReason {
	if record == nil {
		return reasonMalformed
	}
	if record.Version != cacheRecordVersion {
		return reasonSchema
	}
	if record.Key != key.Hex() {
		return reasonKeyMismatch
	}
	if err := validatePrediction(&record.Prediction); err != nil {
		return reasonInvalidPrediction
	}
	want := c.predictionIntegrity(key, &record.Prediction)
	if len(record.Integrity) != len(want) ||
		subtle.ConstantTimeCompare([]byte(record.Integrity), []byte(want)) != 1 {
		return reasonIntegrityMismatch
	}
	return reasonOK
}

func (c *Cache) validRecord(key contentcache.ContentKey, record *cacheRecord) bool {
	return c.recordRejection(key, record) == reasonOK
}

func (c *Cache) noteRejection(reason rejectReason) {
	c.rejected.Add(1)
	switch reason {
	case reasonMalformed:
		c.rejectedMalformed.Add(1)
	case reasonSchema:
		c.rejectedSchema.Add(1)
	case reasonKeyMismatch:
		c.rejectedKey.Add(1)
	case reasonInvalidPrediction:
		c.rejectedInvalid.Add(1)
	case reasonIntegrityMismatch:
		c.rejectedIntegrity.Add(1)
	}
}

func validatePrediction(pred *Prediction) error {
	if pred == nil || pred.PredictedClass < 0 || pred.PredictedClass >= gnnClassCount ||
		len(pred.ClassProbs) != gnnClassCount || !finiteProbability(pred.Confidence) {
		return ErrInvalidPrediction
	}
	bestIndex := 0
	best := float32(-1)
	var sum float64
	for i, probability := range pred.ClassProbs {
		if !finiteProbability(probability) {
			return ErrInvalidPrediction
		}
		sum += float64(probability)
		if probability > best {
			best = probability
			bestIndex = i
		}
	}
	if math.Abs(sum-1) > 1e-3 || bestIndex != pred.PredictedClass ||
		math.Abs(float64(best-pred.Confidence)) > 1e-5 {
		return ErrInvalidPrediction
	}
	return nil
}

func finiteProbability(value float32) bool {
	return value >= 0 && value <= 1 && !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
}

// predictionIntegrity binds a prediction to its key, the inference schema
// version and the model fingerprint. v1 covered those last two only
// indirectly through the key, so a record could not prove which model and
// schema produced it.
func (c *Cache) predictionIntegrity(key contentcache.ContentKey, pred *Prediction) string {
	h := sha256.New()
	h.Write([]byte("omnisec/gnn/cache-record/v2\x00"))
	h.Write(key[:])
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], inferenceSchemaVersion)
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(len(c.fingerprint)))
	h.Write(buf[:])
	h.Write(c.fingerprint)
	binary.LittleEndian.PutUint64(buf[:], uint64(pred.PredictedClass))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(math.Float32bits(pred.Confidence)))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(len(pred.ClassProbs)))
	h.Write(buf[:])
	for _, probability := range pred.ClassProbs {
		binary.LittleEndian.PutUint64(buf[:], uint64(math.Float32bits(probability)))
		h.Write(buf[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RejectedEntries reports how many untrusted on-disk records were discarded
// because their schema, key binding, prediction or integrity check was invalid.
func (c *Cache) RejectedEntries() int64 {
	return c.rejected.Load()
}

// Rejections reports discarded on-disk records grouped by cause.
func (c *Cache) Rejections() RejectionStats {
	return RejectionStats{
		Total:     c.rejected.Load(),
		Malformed: c.rejectedMalformed.Load(),
		Schema:    c.rejectedSchema.Load(),
		Key:       c.rejectedKey.Load(),
		Invalid:   c.rejectedInvalid.Load(),
		Integrity: c.rejectedIntegrity.Load(),
	}
}

// Stats returns hit/miss statistics from the underlying store.
func (c *Cache) Stats() contentcache.Stats {
	return c.store.Stats()
}

// Memo deduplicates identical graph inferences within a single run.
//
// Real targets often contain many copies of the same method (multi-dex,
// bundled libraries), so their graph tensors hash to the same key. Memo
// applies singleflight semantics: the first caller computes the result,
// concurrent and later callers wait and share it, including errors.
type Memo struct {
	mu      sync.Mutex
	entries map[contentcache.ContentKey]*memoEntry
	hits    atomic.Int64
}

type memoEntry struct {
	done chan struct{}
	pred *Prediction
	err  error
}

// NewMemo creates an empty run-local memo table.
func NewMemo() *Memo {
	return &Memo{entries: make(map[contentcache.ContentKey]*memoEntry)}
}

// Do returns the prediction for key, calling compute at most once per key.
// Concurrent callers with the same key block until the first call finishes.
func (m *Memo) Do(key contentcache.ContentKey, compute func() (*Prediction, error)) (*Prediction, error) {
	return m.DoContext(context.Background(), key, compute)
}

// DoContext is Do with cancellation-aware waiting. Cancellation does not
// stop the first computation (the callback owns that context), but duplicate
// callers never remain stuck behind a slow or abandoned inference.
func (m *Memo) DoContext(ctx context.Context, key contentcache.ContentKey, compute func() (*Prediction, error)) (pred *Prediction, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if e, ok := m.entries[key]; ok {
		m.mu.Unlock()
		select {
		case <-e.done:
			m.hits.Add(1)
			return e.pred, e.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e := &memoEntry{done: make(chan struct{})}
	m.entries[key] = e
	m.mu.Unlock()

	completed := false
	defer func() {
		if recovered := recover(); recovered != nil {
			pred = nil
			err = fmt.Errorf("gnncache: inference computation panicked: %v", recovered)
		} else if !completed {
			pred = nil
			err = ErrComputeAborted
		}
		e.pred, e.err = pred, err
		close(e.done)
	}()
	pred, err = compute()
	completed = true
	return pred, err
}

// Hits reports how many Do calls were served from an earlier computation.
func (m *Memo) Hits() int64 {
	return m.hits.Load()
}

// Unique reports how many distinct keys have been computed or started.
func (m *Memo) Unique() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// weightsFileNames are the auto-discovered GNN weight files, in preference
// order. The compact binary encoding is tried first because it is ~5x smaller
// and parses without a JSON pass; both are accepted by the native loader.
var weightsFileNames = []string{"gnn_weights.gnnbuf", "gnn_weights.json"}

// AnalyzerHome returns the per-user analyzer directory (~/.analyzer, i.e.
// C:\Users\<name>\.analyzer on Windows), where the analyzer keeps its
// user-level databases such as trained models. Returns "" when the home
// directory cannot be resolved.
func AnalyzerHome() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".analyzer")
}

// DefaultCacheDir returns the default on-disk location of the GNN cache,
// ~/.analyzer/cache/content, next to the rest of the per-user analyzer
// databases. Returns "" when no home directory is available.
func DefaultCacheDir() string {
	base := AnalyzerHome()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "cache", "content")
}

// DiscoverWeights returns ~/.analyzer/models/gnn_weights.json when that file
// exists, or "". It lets the analyzer pick up real weights automatically,
// without the -gnn-model flag.
func DiscoverWeights() string {
	base := AnalyzerHome()
	if base == "" {
		return ""
	}
	for _, name := range weightsFileNames {
		p := filepath.Join(base, "models", name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
