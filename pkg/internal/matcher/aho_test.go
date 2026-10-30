package matcher

import (
	"reflect"
	"sort"
	"testing"
)

func TestAhoCorasick_Search(t *testing.T) {
	patterns := []string{"he", "she", "his", "hers"}
	ac := NewAhoCorasick(patterns)

	text := "ushers"
	foundIndices := ac.Search(text)
	sort.Ints(foundIndices)

	// Expect indices for "he", "she", "hers"
	// "he" is index 0
	// "she" is index 1
	// "hers" is index 3
	expected := []int{0, 1, 3}
	if !reflect.DeepEqual(foundIndices, expected) {
		t.Errorf("Search(%q) = %v, want %v", text, foundIndices, expected)
	}
}

func TestAhoCorasick_SearchBytes(t *testing.T) {
	patterns := []string{"abc", "bc", "c"}
	ac := NewAhoCorasick(patterns)

	data := []byte("abc")
	found := ac.SearchBytes(data)
	sort.Ints(found)

	// Found indices: 0 (abc), 1 (bc), 2 (c)
	expected := []int{0, 1, 2}
	if !reflect.DeepEqual(found, expected) {
		t.Errorf("SearchBytes() = %v, want %v", found, expected)
	}
}

func TestAhoCorasick_ContainsAny(t *testing.T) {
	ac := NewAhoCorasick([]string{"fire", "water"})

	if !ac.ContainsAny("there is a fire in here") {
		t.Error("Expected true for 'fire'")
	}
	if ac.ContainsAny("only earth and air") {
		t.Error("Expected false for non-matching text")
	}
	if ac.ContainsAny("") {
		t.Error("Expected false for empty text")
	}
}

func TestAhoCorasick_ContainsAnyBytes(t *testing.T) {
	ac := NewAhoCorasick([]string{"match"})
	if !ac.ContainsAnyBytes([]byte("this is a match")) {
		t.Error("Expected true")
	}
}

func TestAhoCorasick_SearchWithPositions(t *testing.T) {
	ac := NewAhoCorasick([]string{"a", "ab"})
	text := "ab"
	matches := ac.SearchWithPositions(text)

	// Match 1: "a" at pos 0 (end pos 0)
	// Match 2: "ab" at pos 1 (end pos 1)
	// Match 3: "a" at fail link skip? No, BFS merges output.
	// Actually "ab" ends at 1, and "a" ends at 0 and at 1 (as suffix of "ab")

	if len(matches) < 2 {
		t.Fatalf("Expected at least 2 matches, got %d", len(matches))
	}
}

func TestAhoCorasick_EmptyPatterns(t *testing.T) {
	ac := NewAhoCorasick([]string{"", ""})
	if ac.PatternCount() != 0 {
		t.Errorf("PatternCount = %d, want 0", ac.PatternCount())
	}
	if ac.Search("anything") != nil {
		t.Error("Expected nil results for empty patterns")
	}
}

func TestAhoCorasick_Stats(t *testing.T) {
	ac := NewAhoCorasick([]string{"test"})
	if ac.PatternCount() != 1 {
		t.Errorf("PatternCount = %d, want 1", ac.PatternCount())
	}
	if ac.NodeCount() < 2 {
		t.Errorf("NodeCount = %d, want > 1", ac.NodeCount())
	}
	if ac.MemoryEstimate() <= 0 {
		t.Error("MemoryEstimate should be > 0")
	}
	if ac.Pattern(0) != "test" {
		t.Errorf("Pattern(0) = %q, want 'test'", ac.Pattern(0))
	}
	if ac.Pattern(99) != "" {
		t.Error("Expected empty string for out of bounds pattern index")
	}
}
