package cfg

import (
	"testing"
)

func TestDefaultCacheConfig(t *testing.T) {
	cfg := DefaultCacheConfig()

	if cfg.Capacity == 0 {
		t.Error("Capacity should be non-zero")
	}

	if cfg.TTL == 0 {
		t.Error("TTL should be non-zero")
	}
}

func TestNewCFGCache(t *testing.T) {
	cache := NewCFGCache(100)

	if cache == nil {
		t.Fatal("NewCFGCache returned nil")
	}

	if got := cache.Capacity(); got != 100 {
		t.Errorf("Capacity = %d, want 100", got)
	}
}

func TestNewCFGCacheWithConfig(t *testing.T) {
	cfg := CacheConfig{
		Capacity: 500,
		TTL:      3600,
	}

	cache := NewCFGCacheWithConfig(cfg)

	if cache == nil {
		t.Fatal("NewCFGCacheWithConfig returned nil")
	}

	if got := cache.Capacity(); got != 500 {
		t.Errorf("Capacity = %d, want 500", got)
	}

	if cache.ttl != 3600 {
		t.Errorf("TTL = %d, want 3600", cache.ttl)
	}
}

func TestCFGCache_GetExtended(t *testing.T) {
	cache := NewCFGCache(100)

	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "nop"},
		},
	}

	// Get non-existent entry
	result := cache.Get(input)
	if result != nil {
		t.Error("Get should return nil for non-existent entry")
	}
}

func TestCFGCache_GetOrBuild(t *testing.T) {
	cache := NewCFGCache(100)

	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "nop"},
			{Opcode: "return"},
		},
	}

	// First call should build
	cfg1 := cache.GetOrBuild(input)
	if cfg1 == nil {
		t.Fatal("GetOrBuild returned nil")
	}

	if cfg1.MethodName != "testMethod" {
		t.Errorf("MethodName = %q, want testMethod", cfg1.MethodName)
	}

	// Second call should return cached
	cfg2 := cache.GetOrBuild(input)
	if cfg2 == nil {
		t.Fatal("GetOrBuild returned nil on second call")
	}

	// Should be same instance (cached)
	if cfg1 != cfg2 {
		t.Error("GetOrBuild should return cached instance")
	}
}

func TestCFGCache_GetOrBuild_DifferentInputs(t *testing.T) {
	cache := NewCFGCache(100)

	input1 := BuildInput{
		MethodName: "method1",
		Instructions: []Instruction{
			{Opcode: "nop"},
		},
	}

	input2 := BuildInput{
		MethodName: "method2",
		Instructions: []Instruction{
			{Opcode: "return"},
		},
	}

	cfg1 := cache.GetOrBuild(input1)
	cfg2 := cache.GetOrBuild(input2)

	if cfg1 == cfg2 {
		t.Error("Different inputs should produce different CFGs")
	}

	if cfg1.MethodName != "method1" {
		t.Errorf("cfg1.MethodName = %q, want method1", cfg1.MethodName)
	}

	if cfg2.MethodName != "method2" {
		t.Errorf("cfg2.MethodName = %q, want method2", cfg2.MethodName)
	}
}

// Benchmark tests
func BenchmarkDefaultCacheConfig(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultCacheConfig()
	}
}

func BenchmarkNewCFGCache(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCFGCache(100)
	}
}

func BenchmarkCFGCache_GetOrBuild(b *testing.B) {
	cache := NewCFGCache(100)
	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "nop"},
			{Opcode: "return"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.GetOrBuild(input)
	}
}

func BenchmarkCFGCache_Get(b *testing.B) {
	cache := NewCFGCache(100)
	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "nop"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(input)
	}
}
