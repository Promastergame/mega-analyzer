package ml

import (
	"bytes"
	"testing"
	"time"
)

func TestPredictorCFGCacheIsBoundedAndClearable(t *testing.T) {
	config := DefaultPredictorConfig()
	config.CFGCacheCapacity = 2
	config.CFGCacheTTL = time.Minute
	predictor := NewPatchPredictorWithConfig(bytes.NewBuffer(nil), config)
	if predictor.CFGCacheStats().Capacity != 2 {
		t.Fatalf("capacity=%d, want 2", predictor.CFGCacheStats().Capacity)
	}
	predictor.ClearCFGCache()
	if stats := predictor.CFGCacheStats(); stats.Size != 0 {
		t.Fatalf("cache size after clear=%d", stats.Size)
	}
}

func TestDefaultPredictorUsesFiniteCFGCachePolicy(t *testing.T) {
	config := DefaultPredictorConfig()
	if config.CFGCacheCapacity <= 0 || config.CFGCacheTTL <= 0 {
		t.Fatalf("invalid bounded CFG policy: capacity=%d ttl=%s", config.CFGCacheCapacity, config.CFGCacheTTL)
	}
}
