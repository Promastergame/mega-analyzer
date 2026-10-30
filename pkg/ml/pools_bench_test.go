package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY OPTIMIZATION BENCHMARKS (Task 6)
// ═══════════════════════════════════════════════════════════════════════════════
//
// These benchmarks verify the memory management optimizations from Task 6:
//   - Object pooling for MethodInfo, ClassInfo
//   - Buffer reuse for string slices
//   - Reduced allocations and GC pressure

// BenchmarkMethodInfo_WithPool measures MethodInfo allocation with pooling
func BenchmarkMethodInfo_WithPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		mi := GetMethodInfo()
		mi.Name = "testMethod"
		mi.ReturnType = "Z"
		mi.Calls = append(mi.Calls, CallInfo{Type: "virtual"})
		PutMethodInfo(mi)
	}
}

// BenchmarkMethodInfo_WithoutPool measures MethodInfo allocation without pooling
func BenchmarkMethodInfo_WithoutPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		mi := &MethodInfo{
			Calls:            make([]CallInfo, 0, 8),
			SecurityCalls:    make([]string, 0, 4),
			StringConsts:     make([]string, 0, 4),
			SecurityStrings:  make([]string, 0, 2),
			MatchedNameParts: make([]string, 0, 2),
			RawBody:          make([]string, 0, 16),
			Name:             "testMethod",
			ReturnType:       "Z",
		}
		mi.Calls = append(mi.Calls, CallInfo{Type: "virtual"})
		// Use all fields to avoid unusedwrite warnings
		_ = mi.Calls
		_ = mi.SecurityCalls
		_ = mi.StringConsts
		_ = mi.SecurityStrings
		_ = mi.MatchedNameParts
		_ = mi.RawBody
		_ = mi.Name
		_ = mi.ReturnType
	}
}

// BenchmarkClassInfo_WithPool measures ClassInfo allocation with pooling
func BenchmarkClassInfo_WithPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ci := GetClassInfo()
		ci.ClassName = "TestClass"
		ci.Methods = append(ci.Methods, MethodInfo{Name: "test"})
		PutClassInfo(ci)
		// Use fields before put to avoid unusedwrite
		_ = ci.ClassName
	}
}

// BenchmarkClassInfo_WithoutPool measures ClassInfo allocation without pooling
func BenchmarkClassInfo_WithoutPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ci := &ClassInfo{
			Methods:   make([]MethodInfo, 0, 16),
			ClassName: "TestClass",
		}
		ci.Methods = append(ci.Methods, MethodInfo{Name: "test"})
		_ = ci.Methods
		_ = ci.ClassName
	}
}

// BenchmarkStringSlice_WithPool measures string slice allocation with pooling
func BenchmarkStringSlice_WithPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		s := GetStringSlice()
		*s = append(*s, "line1", "line2", "line3")
		PutStringSlice(s)
	}
}

// BenchmarkStringSlice_WithoutPool measures string slice allocation without pooling
func BenchmarkStringSlice_WithoutPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		s := make([]string, 0, 64)
		s = append(s, "line1", "line2", "line3")
		_ = s
	}
}

// BenchmarkLineBuffer_WithPool measures line buffer allocation with pooling
func BenchmarkLineBuffer_WithPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := GetLineBuffer()
		buf.Lines = append(buf.Lines, "line1", "line2", "line3")
		PutLineBuffer(buf)
	}
}

// BenchmarkLineBuffer_WithoutPool measures line buffer allocation without pooling
func BenchmarkLineBuffer_WithoutPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := &LineBuffer{
			Lines: make([]string, 0, 256),
		}
		buf.Lines = append(buf.Lines, "line1", "line2", "line3")
		_ = buf
	}
}

// BenchmarkFullAnalysis_WithPools measures full file analysis with pooling
func BenchmarkFullAnalysis_WithPools(b *testing.B) {
	pa := NewPatchAnalyzer()

	content := []byte(`
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public isLicensed()Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method

.method public onCreate()V
    .registers 1
    return-void
.end method
`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ci := pa.AnalyzeSmaliContent("Test.smali", content)
		// In real usage, caller would return ci to pool when done
		_ = ci
	}
}

// BenchmarkBatchAnalysis_WithPools measures batch analysis with pooling
func BenchmarkBatchAnalysis_WithPools(b *testing.B) {
	pa := NewPatchAnalyzer()

	content := []byte(`
.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public isLicensed()Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method
`)

	candidates := make([]AnalysisCandidate, 10)
	for i := range candidates {
		candidates[i] = AnalysisCandidate{
			FilePath: "Test.smali",
			Content:  content,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result := pa.BatchAnalyze(candidates)
		_ = result
	}
}

// BenchmarkPoolReset measures pool reset performance
func BenchmarkPoolReset(b *testing.B) {
	b.Run("MethodInfo", func(b *testing.B) {
		b.ReportAllocs()
		mi := GetMethodInfo()
		mi.Name = "test"
		mi.Calls = append(mi.Calls, CallInfo{}, CallInfo{}, CallInfo{})
		mi.StringConsts = append(mi.StringConsts, "a", "b", "c")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			PutMethodInfo(mi)
			mi = GetMethodInfo()
		}
	})

	b.Run("ClassInfo", func(b *testing.B) {
		b.ReportAllocs()
		ci := GetClassInfo()
		ci.ClassName = "Test"
		ci.Methods = append(ci.Methods, MethodInfo{}, MethodInfo{})

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			PutClassInfo(ci)
			ci = GetClassInfo()
		}
	})
}

// BenchmarkMemoryPressure measures GC pressure with and without pooling
func BenchmarkMemoryPressure(b *testing.B) {
	b.Run("WithPools", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Simulate creating and destroying 100 MethodInfo objects
			for j := 0; j < 100; j++ {
				mi := GetMethodInfo()
				mi.Name = "test"
				mi.Calls = append(mi.Calls, CallInfo{Type: "virtual"})
				PutMethodInfo(mi)
			}
		}
	})

	b.Run("WithoutPools", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Simulate creating and destroying 100 MethodInfo objects
			for j := 0; j < 100; j++ {
				mi := &MethodInfo{
					Calls:            make([]CallInfo, 0, 8),
					SecurityCalls:    make([]string, 0, 4),
					StringConsts:     make([]string, 0, 4),
					SecurityStrings:  make([]string, 0, 2),
					MatchedNameParts: make([]string, 0, 2),
					RawBody:          make([]string, 0, 16),
					Name:             "test",
				}
				mi.Calls = append(mi.Calls, CallInfo{Type: "virtual"})
				// Use all fields to avoid unusedwrite warnings
				_ = mi.Calls
				_ = mi.SecurityCalls
				_ = mi.StringConsts
				_ = mi.SecurityStrings
				_ = mi.MatchedNameParts
				_ = mi.RawBody
				_ = mi.Name
			}
		}
	})
}

// BenchmarkConcurrentPoolAccess measures pool performance under concurrent load
func BenchmarkConcurrentPoolAccess(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mi := GetMethodInfo()
			mi.Name = "test"
			mi.Calls = append(mi.Calls, CallInfo{Type: "virtual"})
			PutMethodInfo(mi)
			_ = mi
		}
	})
}
