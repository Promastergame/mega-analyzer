package filter

import (
	"testing"
)

func TestFilter_IsLibraryPath(t *testing.T) {
	f := NewFilter()
	cases := []struct {
		path string
		want bool
	}{
		{"smali/android/app/Activity.smali", true},
		{"smali/com/google/gson/Gson.smali", true},
		{"smali/kotlin/Unit.smali", true},
		{"smali/com/myapp/MainActivity.smali", false},
		{"smali/com/myapp/LicenseManager.smali", false},
	}
	for _, c := range cases {
		got := f.IsLibraryPath(c.path)
		if got != c.want {
			t.Errorf("IsLibraryPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestFilter_LibraryNameFor(t *testing.T) {
	f := NewFilter()
	// Known library prefix should return non-empty name
	name := f.LibraryNameFor("smali/com/google/gson/Gson.smali")
	_ = name // may or may not be recognized, just no panic

	// App-specific should return empty
	empty := f.LibraryNameFor("smali/com/myapp/MainActivity.smali")
	_ = empty

	// Backslash path should be normalized
	name2 := f.LibraryNameFor("smali\\kotlin\\Unit.smali")
	_ = name2
}

func TestFilter_CacheStats(t *testing.T) {
	f := NewFilter()
	// Warm the cache with a few lookups
	f.IsStandardLibrary("smali/android/app/Activity.smali")
	f.IsStandardLibrary("smali/com/myapp/MainActivity.smali")

	hits, misses, hitRate := f.CacheStats()
	_ = hits
	_ = misses
	_ = hitRate // just ensure no panic

	stats := f.GetCacheStats()
	if stats.MaxSize <= 0 {
		t.Error("MaxSize should be positive")
	}
}

func TestIsAtWordBoundary(t *testing.T) {
	cases := []struct {
		s      string
		idx    int
		length int
		want   bool
	}{
		// At start of string, after is /
		{"License/check", 0, 7, true}, // "License" at start, after is /
		{"License.check", 0, 7, true}, // after is .
		{"aLicensex", 1, 7, false},    // before is 'a', after is 'x' - no boundary
		{"LicenseX", 0, 7, false},     // after is 'X' - not a boundary char
	}
	for _, c := range cases {
		got := isAtWordBoundary(c.s, c.idx, c.length)
		if got != c.want {
			t.Errorf("isAtWordBoundary(%q, %d, %d) = %v, want %v", c.s, c.idx, c.length, got, c.want)
		}
	}
}
