package ml

import (
	"strings"
	"testing"
)

// Benchmarks for string optimization improvements (Task 2)

// BenchmarkStringInterning tests the performance of string interning
func BenchmarkStringInterning(b *testing.B) {
	pa := NewPatchAnalyzer()

	// Common strings that appear repeatedly in smali files
	commonStrings := []string{
		"Z", "V", "I", "J",
		"public", "private", "static", "final",
		"<init>", "<clinit>",
		"virtual", "static", "direct",
		"boolean", "void", "int",
	}

	b.Run("WithInterning", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, s := range commonStrings {
				_ = pa.intern(s)
			}
		}
	})

	b.Run("WithoutInterning", func(b *testing.B) {
		b.ReportAllocs()
		pool := make(map[string]string, 1024)
		for i := 0; i < b.N; i++ {
			for _, s := range commonStrings {
				// Simulate no interning - always allocate
				pool[s] = s
			}
		}
	})
}

// BenchmarkPreLowercasePatterns tests pre-lowercasing vs runtime lowercasing
func BenchmarkPreLowercasePatterns(b *testing.B) {
	patterns := []string{
		"License", "Premium", "Purchase", "Subscription",
		"Billing", "Trial", "Unlock", "Verify",
	}

	b.Run("PreLowercased", func(b *testing.B) {
		// Pre-lowercase at initialization (what we do now)
		lowered := make([]string, len(patterns))
		for i, p := range patterns {
			lowered[i] = strings.ToLower(p)
		}

		b.ResetTimer()
		b.ReportAllocs()

		testStr := "islicensed"
		for i := 0; i < b.N; i++ {
			for _, p := range lowered {
				_ = strings.Contains(testStr, p)
			}
		}
	})

	b.Run("RuntimeLowercasing", func(b *testing.B) {
		// Lowercase on every check (old way)
		b.ReportAllocs()

		testStr := "islicensed"
		for i := 0; i < b.N; i++ {
			for _, p := range patterns {
				_ = strings.Contains(testStr, strings.ToLower(p))
			}
		}
	})
}

// BenchmarkMethodNameInterning tests interning of method names
func BenchmarkMethodNameInterning(b *testing.B) {
	pa := NewPatchAnalyzer()

	// Typical method names that appear many times
	methodNames := []string{
		"onCreate", "onResume", "onPause", "onDestroy",
		"onClick", "onTouch", "onLongClick",
		"isLicensed", "isPremium", "checkLicense",
		"getValue", "setValue", "getData", "setData",
	}

	b.Run("WithInterning", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, name := range methodNames {
				_ = pa.intern(name)
			}
		}
	})

	b.Run("WithoutInterning", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, name := range methodNames {
				// Simulate allocation without interning
				_ = name + ""
			}
		}
	})
}

// BenchmarkCallTypeInterning tests interning of invoke types
func BenchmarkCallTypeInterning(b *testing.B) {
	pa := NewPatchAnalyzer()

	callTypes := []string{
		"virtual", "static", "direct", "interface", "super",
	}

	b.Run("WithInterning", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ct := range callTypes {
				_ = pa.intern(ct)
			}
		}
	})

	b.Run("WithoutInterning", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ct := range callTypes {
				// Allocate new string each time
				result := ct
				_ = result
			}
		}
	})
}

// BenchmarkFullMethodParsing tests the impact on full method parsing
func BenchmarkFullMethodParsing(b *testing.B) {
	pa := NewPatchAnalyzer()

	// Realistic smali method
	methodHeader := ".method public isLicensed()Z"
	methodBody := []string{
		".method public isLicensed()Z",
		"    .registers 2",
		"    const/4 v0, 0x1",
		"    return v0",
		".end method",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = pa.analyzeMethod(methodHeader, methodBody)
	}
}

// BenchmarkStringAllocationReduction measures overall string allocation reduction
func BenchmarkStringAllocationReduction(b *testing.B) {
	// Simulate parsing multiple methods with repeated strings
	pa := NewPatchAnalyzer()

	methods := []struct {
		header string
		body   []string
	}{
		{
			header: ".method public isLicensed()Z",
			body: []string{
				".method public isLicensed()Z",
				"    .registers 2",
				"    const/4 v0, 0x1",
				"    return v0",
				".end method",
			},
		},
		{
			header: ".method public isPremium()Z",
			body: []string{
				".method public isPremium()Z",
				"    .registers 2",
				"    const/4 v0, 0x0",
				"    return v0",
				".end method",
			},
		},
		{
			header: ".method private checkLicense()V",
			body: []string{
				".method private checkLicense()V",
				"    .registers 1",
				"    return-void",
				".end method",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, m := range methods {
			_ = pa.analyzeMethod(m.header, m.body)
		}
	}
}
