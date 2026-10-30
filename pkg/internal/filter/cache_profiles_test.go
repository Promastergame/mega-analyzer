package filter

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════
// LRU Cache tests
// ═══════════════════════════════════════════════════════════════════

func TestNewLRUCache(t *testing.T) {
	cache := NewLRUCache[string, int](10)
	if cache == nil {
		t.Fatal("expected non-nil")
	}
	if cache.Len() != 0 {
		t.Fatal("should be empty")
	}
}

func TestLRUCache_PutAndGet(t *testing.T) {
	cache := NewLRUCache[string, int](5)
	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	v, ok := cache.Get("a")
	if !ok || v != 1 {
		t.Fatalf("Get(a) = %d, %v", v, ok)
	}
	v, ok = cache.Get("b")
	if !ok || v != 2 {
		t.Fatalf("Get(b) = %d, %v", v, ok)
	}
}

func TestLRUCache_Miss(t *testing.T) {
	cache := NewLRUCache[string, int](5)
	_, ok := cache.Get("nonexistent")
	if ok {
		t.Fatal("expected miss")
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	cache := NewLRUCache[string, int](3)
	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)
	cache.Put("d", 4) // should evict "a"

	_, ok := cache.Get("a")
	if ok {
		t.Fatal("a should have been evicted")
	}
	v, ok := cache.Get("d")
	if !ok || v != 4 {
		t.Fatal("d should be present")
	}
}

func TestLRUCache_LRUOrder(t *testing.T) {
	cache := NewLRUCache[string, int](3)
	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	// Access "a" to make it recently used
	cache.Get("a")

	// Add "d" — should evict "b" (least recently used)
	cache.Put("d", 4)

	_, ok := cache.Get("b")
	if ok {
		t.Fatal("b should have been evicted (LRU)")
	}
	_, ok = cache.Get("a")
	if !ok {
		t.Fatal("a should still be present (recently accessed)")
	}
}

func TestLRUCache_Update(t *testing.T) {
	cache := NewLRUCache[string, int](5)
	cache.Put("a", 1)
	cache.Put("a", 2) // update

	v, ok := cache.Get("a")
	if !ok || v != 2 {
		t.Fatalf("Get(a) = %d, %v; want 2", v, ok)
	}
	if cache.Len() != 1 {
		t.Fatalf("Len = %d, want 1", cache.Len())
	}
}

func TestLRUCache_Clear_Full(t *testing.T) {
	cache := NewLRUCache[string, int](5)
	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Clear()

	if cache.Len() != 0 {
		t.Fatalf("Len after clear = %d", cache.Len())
	}
	_, ok := cache.Get("a")
	if ok {
		t.Fatal("should be empty after clear")
	}
}

func TestLRUCache_Stats(t *testing.T) {
	cache := NewLRUCache[string, int](5)
	cache.Put("a", 1)
	cache.Get("a") // hit
	cache.Get("b") // miss
	cache.Get("c") // miss

	hits, misses, hitRate := cache.Stats()
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if misses != 2 {
		t.Fatalf("misses = %d, want 2", misses)
	}
	expected := 1.0 / 3.0
	if hitRate < expected-0.01 || hitRate > expected+0.01 {
		t.Fatalf("hitRate = %f, want ~%f", hitRate, expected)
	}
}

func TestLRUCache_Stats_Empty(t *testing.T) {
	cache := NewLRUCache[string, int](5)
	hits, misses, hitRate := cache.Stats()
	if hits != 0 || misses != 0 || hitRate != 0 {
		t.Fatalf("empty stats: hits=%d, misses=%d, rate=%f", hits, misses, hitRate)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Profile tests
// ═══════════════════════════════════════════════════════════════════

func TestAllProfiles_Count(t *testing.T) {
	profiles := AllProfiles()
	if len(profiles) < 4 {
		t.Fatalf("expected at least 4 profiles, got %d", len(profiles))
	}
}

func TestProfileDescription_All(t *testing.T) {
	for _, p := range AllProfiles() {
		desc := ProfileDescription(p)
		if desc == "" {
			t.Errorf("profile %v has empty description", p)
		}
	}
}

func TestIsValidProfile(t *testing.T) {
	for _, p := range AllProfiles() {
		if !IsValidProfile(p) {
			t.Errorf("profile %v should be valid", p)
		}
	}
	if IsValidProfile("nonexistent_profile") {
		t.Fatal("invalid profile should not be valid")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"strict", true},
		{"loose", true},
		{"paranoid", true},
		{"audit", true},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		_, ok := ParseProfile(tt.input)
		if ok != tt.valid {
			t.Errorf("ParseProfile(%q) valid=%v, want %v", tt.input, ok, tt.valid)
		}
	}
}

func TestGetProfile(t *testing.T) {
	for _, p := range AllProfiles() {
		rules := GetProfile(p)
		// Should return non-zero rules
		if rules.Scoring.BaseImportance == 0 && len(rules.StandardLibraries) == 0 && len(rules.KeywordWeights) == 0 {
			t.Errorf("GetProfile(%v) returned empty rules", p)
		}
	}
}

func TestGetModifier(t *testing.T) {
	for _, p := range AllProfiles() {
		mod := GetModifier(p)
		if mod == nil {
			t.Errorf("GetModifier(%v) returned nil", p)
			continue
		}
		if mod.Name() == "" {
			t.Errorf("modifier for %v has empty name", p)
		}
		if mod.Description() == "" {
			t.Errorf("modifier for %v has empty description", p)
		}
	}
}

func TestProfileBuilder(t *testing.T) {
	builder := NewProfileBuilder(ProfileStrict)
	if builder == nil {
		t.Fatal("expected non-nil builder")
	}

	rules := builder.
		WithBaseImportance(50).
		WithDampening(0.5, 0.1, 0.9).
		Build()

	if rules.Scoring.BaseImportance != 50 {
		t.Fatalf("BaseImportance = %d, want 50", rules.Scoring.BaseImportance)
	}
}

func TestProfileBuilder_WithoutLibraries(t *testing.T) {
	builder := NewProfileBuilder(ProfileStrict)
	rules := builder.WithoutLibraries("google", "android").Build()
	// Should have removed some libraries
	_ = rules
}

func TestProfileBuilder_WithKeyword(t *testing.T) {
	builder := NewProfileBuilder(ProfileStrict)
	rules := builder.WithKeyword("custom_keyword", KeywordConfig{
		Weight: 100,
	}).Build()
	// Should have added the keyword
	found := false
	for name := range rules.KeywordWeights {
		if name == "custom_keyword" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom keyword should be in rules")
	}
}

func TestProfileBuilder_WithoutKeywords(t *testing.T) {
	builder := NewProfileBuilder(ProfileStrict)
	rules := builder.WithoutKeywords("license", "premium").Build()
	// Should have removed those keywords
	if _, ok := rules.KeywordWeights["license"]; ok {
		t.Fatal("license keyword should have been removed")
	}
}

func TestCompareProfiles(t *testing.T) {
	diff := CompareProfiles(ProfileStrict, ProfileLoose)
	// Should have some differences
	_ = diff
}

func TestFilterRules_DeepCopy(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	copy := rules.DeepCopy()
	if copy == nil {
		t.Fatal("DeepCopy should not return nil")
	}
	// Modifying copy should not affect original
	copy.Scoring.BaseImportance = 999
	if rules.Scoring.BaseImportance == 999 {
		t.Fatal("DeepCopy should be independent")
	}
}
