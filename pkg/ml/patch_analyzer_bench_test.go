package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK SUITE: PatchAnalyzer Performance Baseline
//
// Establishes baseline metrics for:
// - CPU time per method analysis
// - Memory allocations per operation
// - Throughput (methods/second)
// - String operation overhead
// - Pattern matching performance
//
// Run with: go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof
// ═══════════════════════════════════════════════════════════════════════════════

// Sample smali method for benchmarking
const sampleSmaliMethod = `.method public isLicensed()Z
    .registers 4
    .line 42

    const/4 v0, 0x0

    invoke-virtual {p0}, Lcom/app/LicenseChecker;->checkLicense()Z
    move-result v1

    if-eqz v1, :cond_false

    const/4 v0, 0x1
    return v0

    :cond_false
    const/4 v0, 0x0
    return v0
.end method`

const sampleSmaliClass = `.class public Lcom/app/security/LicenseChecker;
.super Ljava/lang/Object;

` + sampleSmaliMethod + `

.method public checkPremium()Z
    .registers 2
    
    invoke-virtual {p0}, Lcom/app/security/LicenseChecker;->isLicensed()Z
    move-result v0
    
    return v0
.end method

.method public isRooted()Z
    .registers 3
    
    const-string v0, "/system/xbin/su"
    
    new-instance v1, Ljava/io/File;
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    
    invoke-virtual {v1}, Ljava/io/File;->exists()Z
    move-result v2
    
    return v2
.end method
`

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Full File Analysis
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkAnalyzeSmaliContent(b *testing.B) {
	pa := NewPatchAnalyzer()
	content := []byte(sampleSmaliClass)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.AnalyzeSmaliContent("smali/com/app/security/LicenseChecker.smali", content)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Method Extraction
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkExtractMethods(b *testing.B) {
	pa := NewPatchAnalyzer()
	lines := splitLines([]byte(sampleSmaliClass))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		classInfo := &ClassInfo{
			FilePath: "test.smali",
			Methods:  make([]MethodInfo, 0, 16),
		}
		pa.extractMethods(classInfo, lines)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Single Method Analysis
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkAnalyzeMethod(b *testing.B) {
	pa := NewPatchAnalyzer()
	header := ".method public isLicensed()Z"
	body := splitLines([]byte(sampleSmaliMethod))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.analyzeMethod(header, body)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Pattern Matching
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkMatchVulnerablePatterns(b *testing.B) {
	pa := NewPatchAnalyzer()

	// Create a method with security characteristics
	mi := &MethodInfo{
		Name:             "isLicensed",
		NameLower:        "islicensed",
		ClassName:        "Lcom/app/security/LicenseChecker;",
		FilePath:         "smali/com/app/security/LicenseChecker.smali",
		ReturnType:       "Z",
		ReturnsBoolean:   true,
		HasCheckPrefix:   true,
		HasSecurityName:  true,
		IsShortMethod:    true,
		HasDualReturn:    true,
		HasIfWithReturn:  true,
		InstructionCount: 12,
		IfCheckCount:     1,
		ReturnCount:      2,
		IsAppCode:        true,
		Calls:            []CallInfo{{Type: "virtual", Method: "checkLicense", IsSecurityRelated: true}},
		StringConsts:     []string{},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.MatchVulnerablePatterns(mi)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: String Operations
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkSplitLines(b *testing.B) {
	content := []byte(sampleSmaliClass)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = splitLines(content)
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	path := "smali\\com\\app\\security\\LicenseChecker.smali"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = normalizePath(path)
	}
}

func BenchmarkIsLibraryPath(b *testing.B) {
	paths := []string{
		"com/app/security/LicenseChecker",
		"com/google/android/gms/ads/AdView",
		"androidx/appcompat/app/AppCompatActivity",
		"com/myapp/premium/PremiumChecker",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = IsLibraryPath(path)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Method Name Analysis
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkAnalyzeMethodName(b *testing.B) {
	pa := NewPatchAnalyzer()
	mi := &MethodInfo{
		Name:      "isLicensedPremiumUser",
		NameLower: "islicensedpremiumuser",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pa.analyzeMethodName(mi)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Security Pattern Matching
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkMatchSecurityPatterns(b *testing.B) {
	pa := NewPatchAnalyzer()
	mi := &MethodInfo{
		Calls: []CallInfo{
			{FullCall: "com/app/licensecheck;->checklicense", IsSecurityRelated: false},
			{FullCall: "android/content/packagemanager;->getpackageinfo", IsSecurityRelated: false},
		},
		StringConsts: []string{
			"license_key",
			"premium_status",
			"trial_expired",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pa.matchSecurityPatterns(mi)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: Batch Analysis
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkBatchAnalyze(b *testing.B) {
	pa := NewPatchAnalyzer()

	// Create 10 candidates
	candidates := make([]AnalysisCandidate, 10)
	for i := range candidates {
		candidates[i] = AnalysisCandidate{
			FilePath:  "smali/com/app/Test.smali",
			Content:   []byte(sampleSmaliClass),
			IsAppCode: true,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.BatchAnalyze(candidates)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASELINE: IsWorthAnalyzing (Fast Path)
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkIsWorthAnalyzing(b *testing.B) {
	pa := NewPatchAnalyzer()

	methods := []MethodInfo{
		// Worth analyzing
		{
			Name:             "isLicensed",
			ReturnsBoolean:   true,
			HasCheckPrefix:   true,
			InstructionCount: 15,
		},
		// Not worth (constructor)
		{
			Name:             "<init>",
			IsConstructor:    true,
			InstructionCount: 5,
		},
		// Not worth (too short)
		{
			Name:             "getValue",
			InstructionCount: 1,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := range methods {
			_ = pa.IsWorthAnalyzing(&methods[j])
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY ALLOCATION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkMethodInfoAllocation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		mi := &MethodInfo{
			Name:         "testMethod",
			ClassName:    "TestClass",
			FilePath:     "test.smali",
			Calls:        make([]CallInfo, 0, 8),
			StringConsts: make([]string, 0, 8),
		}
		// Use the struct to avoid unusedwrite warnings
		_ = mi.Name
		_ = mi.ClassName
		_ = mi.FilePath
		_ = mi.Calls
		_ = mi.StringConsts
	}
}

func BenchmarkCallInfoSliceGrowth(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		calls := make([]CallInfo, 0, 8)
		for j := 0; j < 20; j++ {
			calls = append(calls, CallInfo{
				Type:   "virtual",
				Method: "testMethod",
			})
		}
	}
}
