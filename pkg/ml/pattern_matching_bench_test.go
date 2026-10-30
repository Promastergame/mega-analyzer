package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN MATCHING OPTIMIZATION BENCHMARKS (Task 4)
// ═══════════════════════════════════════════════════════════════════════════════
//
// These benchmarks verify the pattern matching optimizations from Task 4:
//   - Indexed lookup structures (O(1) vs O(N))
//   - Pattern index for vulnerable patterns
//   - Reduced search space with smart filtering

// BenchmarkPatternIndex_Build measures pattern index construction time
func BenchmarkPatternIndex_Build(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BuildPatternIndex()
	}
}

// BenchmarkPatternIndex_FindCandidates measures indexed lookup performance
func BenchmarkPatternIndex_FindCandidates(b *testing.B) {
	idx := GetPatternIndex()

	// Test method with license-related name
	mi := &MethodInfo{
		Name:       "isLicensed",
		NameLower:  "islicensed",
		ClassName:  "Lcom/app/LicenseChecker;",
		ReturnType: "Z",
		Calls: []CallInfo{
			{FullCall: "landroid/content/pm/packagemanager;->getinstallerpackagename"},
		},
		StringConsts: []string{"license", "premium"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = idx.FindCandidates(mi)
	}
}

// BenchmarkPatternIndex_FindCandidates_NoMatch measures performance when no candidates found
func BenchmarkPatternIndex_FindCandidates_NoMatch(b *testing.B) {
	idx := GetPatternIndex()

	// Test method with no security-related content
	mi := &MethodInfo{
		Name:         "onCreate",
		NameLower:    "oncreate",
		ClassName:    "Landroid/app/Activity;",
		ReturnType:   "V",
		Calls:        []CallInfo{},
		StringConsts: []string{},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = idx.FindCandidates(mi)
	}
}

// BenchmarkMatchVulnerablePatterns_WithIndex measures pattern matching with indexed lookup
func BenchmarkMatchVulnerablePatterns_WithIndex(b *testing.B) {
	pa := NewPatchAnalyzer()

	// Realistic license check method
	mi := &MethodInfo{
		Name:             "isLicensed",
		NameLower:        "islicensed",
		ClassName:        "Lcom/app/security/LicenseChecker;",
		ReturnType:       "Z",
		ReturnsBoolean:   true,
		InstructionCount: 15,
		IfCheckCount:     2,
		ReturnCount:      2,
		HasDualReturn:    true,
		HasIfWithReturn:  true,
		IsShortMethod:    true,
		Calls: []CallInfo{
			{
				Type:     "virtual",
				Class:    "android/content/pm/PackageManager",
				Method:   "getInstallerPackageName",
				FullCall: "landroid/content/pm/packagemanager;->getinstallerpackagename",
			},
		},
		StringConsts:    []string{"com.android.vending", "license"},
		HasSecurityName: true,
		HasCheckPrefix:  true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.MatchVulnerablePatterns(mi)
	}
}

// BenchmarkMatchVulnerablePatterns_LinearSearch simulates old O(N) approach
func BenchmarkMatchVulnerablePatterns_LinearSearch(b *testing.B) {
	pa := NewPatchAnalyzer()

	mi := &MethodInfo{
		Name:             "isLicensed",
		NameLower:        "islicensed",
		ClassName:        "Lcom/app/security/LicenseChecker;",
		ReturnType:       "Z",
		ReturnsBoolean:   true,
		InstructionCount: 15,
		IfCheckCount:     2,
		ReturnCount:      2,
		HasDualReturn:    true,
		HasIfWithReturn:  true,
		IsShortMethod:    true,
		Calls: []CallInfo{
			{
				Type:     "virtual",
				Class:    "android/content/pm/PackageManager",
				Method:   "getInstallerPackageName",
				FullCall: "landroid/content/pm/packagemanager;->getinstallerpackagename",
			},
		},
		StringConsts:    []string{"com.android.vending", "license"},
		HasSecurityName: true,
		HasCheckPrefix:  true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	// Simulate old linear search through all patterns
	for i := 0; i < b.N; i++ {
		matches := make([]PatternMatch, 0, 4)
		for j := range VulnerablePatterns {
			vp := &VulnerablePatterns[j]
			pm := pa.matchSinglePattern(mi, vp)
			if pm != nil && pm.MatchScore >= vp.MinMatchScore {
				matches = append(matches, *pm)
			}
		}
		_ = matches
	}
}

// BenchmarkPatternIndex_ByReturnType measures return type index lookup
func BenchmarkPatternIndex_ByReturnType(b *testing.B) {
	idx := GetPatternIndex()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = idx.FindByReturnType("Z")
	}
}

// BenchmarkPatternIndex_ByCategory measures category index lookup
func BenchmarkPatternIndex_ByCategory(b *testing.B) {
	idx := GetPatternIndex()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = idx.FindByCategory("license")
	}
}

// BenchmarkPatternMatching_RootDetection measures root detection pattern matching
func BenchmarkPatternMatching_RootDetection(b *testing.B) {
	pa := NewPatchAnalyzer()

	mi := &MethodInfo{
		Name:             "isRooted",
		NameLower:        "isrooted",
		ClassName:        "Lcom/app/security/RootChecker;",
		ReturnType:       "Z",
		ReturnsBoolean:   true,
		InstructionCount: 20,
		IfCheckCount:     3,
		ReturnCount:      2,
		HasDualReturn:    true,
		IsShortMethod:    true,
		Calls: []CallInfo{
			{FullCall: "ljava/io/file;->exists"},
		},
		StringConsts:    []string{"/system/bin/su", "/system/xbin/su"},
		HasSecurityName: true,
		HasCheckPrefix:  true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.MatchVulnerablePatterns(mi)
	}
}

// BenchmarkPatternMatching_EmulatorDetection measures emulator detection pattern matching
func BenchmarkPatternMatching_EmulatorDetection(b *testing.B) {
	pa := NewPatchAnalyzer()

	mi := &MethodInfo{
		Name:             "isEmulator",
		NameLower:        "isemulator",
		ClassName:        "Lcom/app/security/EmulatorDetector;",
		ReturnType:       "Z",
		ReturnsBoolean:   true,
		InstructionCount: 25,
		IfCheckCount:     4,
		ReturnCount:      2,
		HasDualReturn:    true,
		IsShortMethod:    true,
		Calls: []CallInfo{
			{FullCall: "landroid/os/build;->getserial"},
		},
		StringConsts:    []string{"generic", "goldfish", "emulator"},
		HasSecurityName: true,
		HasCheckPrefix:  true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pa.MatchVulnerablePatterns(mi)
	}
}

// BenchmarkPatternMatching_Batch measures batch pattern matching performance
func BenchmarkPatternMatching_Batch(b *testing.B) {
	pa := NewPatchAnalyzer()

	methods := []*MethodInfo{
		{
			Name: "isLicensed", NameLower: "islicensed",
			ReturnType: "Z", ReturnsBoolean: true,
			HasSecurityName: true, HasCheckPrefix: true,
		},
		{
			Name: "isRooted", NameLower: "isrooted",
			ReturnType: "Z", ReturnsBoolean: true,
			HasSecurityName: true, HasCheckPrefix: true,
		},
		{
			Name: "isPremium", NameLower: "ispremium",
			ReturnType: "Z", ReturnsBoolean: true,
			HasSecurityName: true, HasCheckPrefix: true,
		},
		{
			Name: "checkSubscription", NameLower: "checksubscription",
			ReturnType: "Z", ReturnsBoolean: true,
			HasSecurityName: true, HasCheckPrefix: true,
		},
		{
			Name: "isEmulator", NameLower: "isemulator",
			ReturnType: "Z", ReturnsBoolean: true,
			HasSecurityName: true, HasCheckPrefix: true,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, mi := range methods {
			_ = pa.MatchVulnerablePatterns(mi)
		}
	}
}

// BenchmarkPatternIndex_Stats measures stats calculation performance
func BenchmarkPatternIndex_Stats(b *testing.B) {
	idx := GetPatternIndex()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = idx.Stats()
	}
}
