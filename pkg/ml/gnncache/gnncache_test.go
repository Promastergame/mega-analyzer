package gnncache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/contentcache"
)

var (
	testFingerprintA = strings.Repeat("aa", 32)
	testFingerprintB = strings.Repeat("dd", 32)
)

// gnnEntryPath mirrors the store's on-disk layout for a GNN cache entry.
func gnnEntryPath(dir string, key contentcache.ContentKey) string {
	version := contentcache.DefaultStoreConfig().Version
	return filepath.Join(dir, fmt.Sprintf("v%d", version), "gnn", key.Hex()[:2], key.Hex()[2:])
}

func sampleGraph() *GraphTensor {
	return &GraphTensor{
		RowPtrs:    []uint64{0, 1, 2},
		ColIndices: []uint64{1, 0},
		Features:   []float32{0.1, 0.2, 0.3, 0.4},
		NumNodes:   2,
		FeatureDim: 2,
	}
}

func TestModelFingerprintDummy(t *testing.T) {
	for _, path := range []string{"", DummyModelPath} {
		fp, err := ModelFingerprint(path)
		if err != nil {
			t.Fatalf("ModelFingerprint(%q) error: %v", path, err)
		}
		if fp != "" {
			t.Fatalf("ModelFingerprint(%q) = %q, want empty", path, fp)
		}
	}
}

func TestModelFingerprintFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := os.WriteFile(a, []byte(`{"w":[1,2,3]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"w":[9,9,9]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fpA1, err := ModelFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fpA2, err := ModelFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fpB, err := ModelFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	if fpA1 == "" || fpA1 != fpA2 {
		t.Fatalf("fingerprint not stable: %q vs %q", fpA1, fpA2)
	}
	if fpA1 == fpB {
		t.Fatal("different weight files produced the same fingerprint")
	}
	if _, err := ModelFingerprint(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error for missing weight file")
	}
}

func TestOpenRejectsDummy(t *testing.T) {
	if _, err := Open(t.TempDir(), 0, ""); err != ErrDummyModel {
		t.Fatalf("Open with empty fingerprint: got %v, want ErrDummyModel", err)
	}
	for _, fingerprint := range []string{"abc", strings.Repeat("z", 64)} {
		if _, err := Open(t.TempDir(), 0, fingerprint); !errors.Is(err, ErrInvalidFingerprint) {
			t.Fatalf("Open with fingerprint %q: got %v, want ErrInvalidFingerprint", fingerprint, err)
		}
	}
	if _, err := Open(t.TempDir(), -1, testFingerprintA); err == nil {
		t.Fatal("Open accepted a negative disk limit")
	}
}

func TestKeyDeterministicAndSensitive(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	k1 := c.Key(sampleGraph())
	k2 := c.Key(sampleGraph())
	if k1 != k2 {
		t.Fatal("same graph produced different keys")
	}

	g := sampleGraph()
	g.Features[0] = 0.99
	if c.Key(g) == k1 {
		t.Fatal("feature change did not change the key")
	}

	g = sampleGraph()
	g.ColIndices = []uint64{0, 1}
	if c.Key(g) == k1 {
		t.Fatal("edge change did not change the key")
	}

	c2, err := Open(t.TempDir(), 0, testFingerprintB)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Key(sampleGraph()) == k1 {
		t.Fatal("different model fingerprint did not change the key")
	}
}

func TestPutGetRoundtripAndPersistence(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	key := c.Key(sampleGraph())

	if _, ok := c.Get(key); ok {
		t.Fatal("unexpected cache hit before Put")
	}

	want := &Prediction{PredictedClass: 2, Confidence: 0.87, ClassProbs: []float32{0.01, 0.02, 0.87, 0.1, 0, 0, 0, 0}}
	if err := c.Put(key, want); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit after Put")
	}
	if got.PredictedClass != want.PredictedClass || got.Confidence != want.Confidence || len(got.ClassProbs) != len(want.ClassProbs) {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, want)
	}

	// A fresh cache over the same directory and model must hit from disk.
	c2, err := Open(dir, 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c2.Get(c2.Key(sampleGraph())); !ok {
		t.Fatal("expected persistent cache hit from a fresh store")
	}
}

func TestGraphKeyDeterministicAndModelIndependent(t *testing.T) {
	k1 := GraphKey(sampleGraph())
	k2 := GraphKey(sampleGraph())
	if k1 != k2 {
		t.Fatal("same graph produced different graph keys")
	}
	g := sampleGraph()
	g.Features[0] = 0.5
	if GraphKey(g) == k1 {
		t.Fatal("feature change did not change the graph key")
	}
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	if c.Key(sampleGraph()) == k1 {
		t.Fatal("Cache.Key must differ from GraphKey (fingerprint is mixed in)")
	}
}

func TestPutRejectsMalformedPrediction(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	key := c.Key(sampleGraph())
	tests := []*Prediction{
		nil,
		{PredictedClass: 8, Confidence: 1, ClassProbs: []float32{0, 0, 0, 0, 0, 0, 0, 1}},
		{PredictedClass: 0, Confidence: 0.8, ClassProbs: []float32{0.8, 0.1, 0.1, 0, 0, 0, 0, 0.1}},
		{PredictedClass: 1, Confidence: 0.8, ClassProbs: []float32{0.8, 0.2, 0, 0, 0, 0, 0, 0}},
	}
	for i, pred := range tests {
		if err := c.Put(key, pred); !errors.Is(err, ErrInvalidPrediction) {
			t.Errorf("case %d: Put error = %v, want ErrInvalidPrediction", i, err)
		}
	}
	if _, ok := c.Get(key); ok {
		t.Fatal("invalid prediction was cached")
	}
}

func TestGetRejectsAndDeletesTamperedRecord(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	key := c.Key(sampleGraph())
	pred := &Prediction{
		PredictedClass: 0,
		Confidence:     0.8,
		ClassProbs:     []float32{0.8, 0.1, 0.05, 0.025, 0.01, 0.01, 0.005, 0},
	}
	if err := c.Put(key, pred); err != nil {
		t.Fatal(err)
	}

	// Rewrite the payload through the store so the on-disk framing stays
	// valid: this test targets the record-level integrity tag, not the
	// store-level checksum.
	path := gnnEntryPath(dir, key)
	data, ok := c.store.Get(contentcache.NamespaceGNN, key)
	if !ok {
		t.Fatal("stored record not readable")
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record["integrity"] = strings.Repeat("0", 64)
	tampered, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.Put(contentcache.NamespaceGNN, key, tampered); err != nil {
		t.Fatal(err)
	}

	// Use a fresh Store so the valid hot-cache copy cannot mask disk damage.
	fresh, err := Open(dir, 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Get(key); ok {
		t.Fatal("tampered record was accepted")
	}
	if fresh.RejectedEntries() != 1 {
		t.Fatalf("RejectedEntries = %d, want 1", fresh.RejectedEntries())
	}
	if rej := fresh.Rejections(); rej.Integrity != 1 {
		t.Fatalf("Rejections = %+v, want one integrity mismatch", rej)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("tampered record was not deleted: %v", err)
	}
}

func TestGetRejectsRecordSwappedBetweenKeys(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	g1 := sampleGraph()
	g2 := sampleGraph()
	g2.Features[0] = 0.9
	k1, k2 := c.Key(g1), c.Key(g2)
	pred := &Prediction{PredictedClass: 0, Confidence: 1, ClassProbs: []float32{1, 0, 0, 0, 0, 0, 0, 0}}
	if err := c.Put(k1, pred); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(k2, pred); err != nil {
		t.Fatal(err)
	}
	// Copy the raw framed file of k1 over k2. The store's key binding must
	// reject it before the record-level check even runs.
	data, err := os.ReadFile(gnnEntryPath(dir, k1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gnnEntryPath(dir, k2), data, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(dir, 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Get(k2); ok {
		t.Fatal("record copied from another content key was accepted")
	}
}

func TestMemoDedupSequential(t *testing.T) {
	m := NewMemo()
	key := GraphKey(sampleGraph())
	calls := 0
	compute := func() (*Prediction, error) {
		calls++
		return &Prediction{PredictedClass: 3, Confidence: 0.9}, nil
	}
	p1, err := m.Do(key, compute)
	if err != nil || p1 == nil || p1.PredictedClass != 3 {
		t.Fatalf("first Do: %+v, %v", p1, err)
	}
	p2, err := m.Do(key, compute)
	if err != nil || p2 != p1 {
		t.Fatal("second Do did not share the first result")
	}
	if calls != 1 {
		t.Fatalf("compute called %d times, want 1", calls)
	}
	if m.Hits() != 1 || m.Unique() != 1 {
		t.Fatalf("hits = %d, unique = %d; want 1, 1", m.Hits(), m.Unique())
	}
}

func TestMemoSingleflightConcurrent(t *testing.T) {
	m := NewMemo()
	key := GraphKey(sampleGraph())
	var calls atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			p, err := m.Do(key, func() (*Prediction, error) {
				calls.Add(1)
				time.Sleep(10 * time.Millisecond)
				return &Prediction{PredictedClass: 1, Confidence: 0.5}, nil
			})
			if err != nil || p == nil || p.PredictedClass != 1 {
				t.Errorf("Do returned %+v, %v", p, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("compute ran %d times, want 1", calls.Load())
	}
	if m.Hits() != 15 {
		t.Fatalf("hits = %d, want 15", m.Hits())
	}
}

func TestMemoErrorShared(t *testing.T) {
	m := NewMemo()
	key := GraphKey(sampleGraph())
	calls := 0
	wantErr := errors.New("boom")
	_, err1 := m.Do(key, func() (*Prediction, error) { calls++; return nil, wantErr })
	_, err2 := m.Do(key, func() (*Prediction, error) { calls++; return nil, wantErr })
	if err1 != wantErr || err2 != wantErr {
		t.Fatalf("errors not shared: %v, %v", err1, err2)
	}
	if calls != 1 {
		t.Fatalf("compute called %d times, want 1", calls)
	}
}

func TestMemoWaiterHonorsCancellation(t *testing.T) {
	m := NewMemo()
	key := GraphKey(sampleGraph())
	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = m.Do(key, func() (*Prediction, error) {
			close(started)
			<-release
			return &Prediction{PredictedClass: 1}, nil
		})
	}()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.DoContext(ctx, key, func() (*Prediction, error) {
		t.Fatal("duplicate waiter must not compute")
		return nil, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DoContext error = %v, want context.Canceled", err)
	}
	close(release)
}

func TestMemoPanicUnblocksWaiters(t *testing.T) {
	m := NewMemo()
	key := GraphKey(sampleGraph())
	started := make(chan struct{})
	release := make(chan struct{})
	firstErr := make(chan error, 1)
	go func() {
		_, err := m.Do(key, func() (*Prediction, error) {
			close(started)
			<-release
			panic("boom")
		})
		firstErr <- err
	}()
	<-started

	waiterErr := make(chan error, 1)
	go func() {
		_, err := m.Do(key, func() (*Prediction, error) {
			t.Error("duplicate waiter must not compute")
			return nil, nil
		})
		waiterErr <- err
	}()
	close(release)

	for name, errCh := range map[string]<-chan error{"first": firstErr, "waiter": waiterErr} {
		select {
		case err := <-errCh:
			if err == nil || !strings.Contains(err.Error(), "panicked: boom") {
				t.Errorf("%s error = %v, want shared panic error", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s caller remained blocked", name)
		}
	}
}

func setTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)        // unix
	t.Setenv("USERPROFILE", home) // windows
	return home
}

func TestDefaultCacheDirUnderHome(t *testing.T) {
	home := setTempHome(t)
	got := DefaultCacheDir()
	want := filepath.Join(home, ".analyzer", "cache", "content")
	if got != want {
		t.Fatalf("DefaultCacheDir = %q, want %q", got, want)
	}
}

func TestDiscoverWeights(t *testing.T) {
	home := setTempHome(t)
	if p := DiscoverWeights(); p != "" {
		t.Fatalf("unexpected discovery in empty home: %q", p)
	}
	dir := filepath.Join(home, ".analyzer", "models")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "gnn_weights.json")
	if err := os.WriteFile(want, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := DiscoverWeights(); p != want {
		t.Fatalf("DiscoverWeights = %q, want %q", p, want)
	}
}
