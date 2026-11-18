// pkg/internal/analyzer/scoring_test.go
package analyzer

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/filter"
	"mega-analyzer/pkg/internal/types"
)

func newTestScorer() *Scorer {
	cfg := config.DefaultConfig()
	f := filter.NewFilter()
	return NewScorer(cfg, f)
}

func newTestAnalysis(path string, isApp bool, importance int) *types.FileAnalysis {
	a := types.NewFileAnalysis(path, types.FileTypeSmali, 1000)
	a.IsAppCode = isApp
	a.Importance = importance
	return a
}

func addMatch(a *types.FileAnalysis, cat types.Category) {
	a.Matches = append(a.Matches, types.Match{
		Categorized: types.Categorized{Category: cat},
		Scored:      types.Scored{Score: 5.0},
		Pattern:     "test",
		IsCritical:  types.GetCategoryInfo(cat).IsCritical,
	})
}

// ============================================================================
// NewScorer
// ============================================================================

func TestNewScorer(t *testing.T) {
	s := newTestScorer()
	if s == nil {
		t.Fatal("NewScorer returned nil")
	}
}

func TestNewScorerWithWeights(t *testing.T) {
	cfg := config.DefaultConfig()
	w := ScoringWeights{
		ImportanceMultiplier: 5.0,
		CriticalPriority:     10.0,
		DecisionPointValue:   20.0,
	}
	s := NewScorerWithWeights(cfg, nil, w)
	if s == nil {
		t.Fatal("NewScorerWithWeights returned nil")
	}
	if s.weights.ImportanceMultiplier != 5.0 {
		t.Errorf("ImportanceMultiplier = %f", s.weights.ImportanceMultiplier)
	}
}

// ============================================================================
// ScoreFile
// ============================================================================

func TestScoreFile_LibraryCode(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/android/app/Activity.smali", false, 5)
	addMatch(a, types.CategoryLicenseCheck)

	score, reasons := s.ScoreFile(a)
	if score != 0 {
		t.Errorf("Library code score = %f, want 0", score)
	}
	if len(reasons) == 0 {
		t.Error("expected reason for skipping")
	}
}

func TestScoreFile_StandardLibrary(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/android/app/Activity.smali", true, 5)

	score, _ := s.ScoreFile(a)
	if score != 0 {
		t.Errorf("Standard library score = %f, want 0", score)
	}
}

func TestScoreFile_CriticalMatches(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/License.smali", true, 8)
	addMatch(a, types.CategoryLicenseCheck)
	addMatch(a, types.CategoryLicenseCheck)
	addMatch(a, types.CategoryBillingClient)

	score, reasons := s.ScoreFile(a)
	if score <= 0 {
		t.Errorf("Critical matches score = %f, want > 0", score)
	}
	if len(reasons) == 0 {
		t.Error("expected reasons")
	}
}

func TestScoreFile_WithDecisionPoints(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/Check.smali", true, 5)
	addMatch(a, types.CategoryLicenseCheck)
	a.DecisionPoints = append(a.DecisionPoints, types.DecisionPoint{
		Method: "isPremium",
		Type:   types.DecisionBooleanReturn,
	})

	bd := s.ScoreFileDetailed(a)
	if bd.DecisionBonus <= 0 {
		t.Errorf("DecisionBonus = %f, want > 0", bd.DecisionBonus)
	}
	if bd.DecisionPointCount != 1 {
		t.Errorf("DecisionPointCount = %d", bd.DecisionPointCount)
	}
}

func TestScoreFile_HighEntropy(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/Config.smali", true, 5)
	addMatch(a, types.CategoryNetworkEndpoint)
	a.Entropy = 7.5

	bd := s.ScoreFileDetailed(a)
	if bd.EntropyBonus <= 0 {
		t.Errorf("EntropyBonus = %f, want > 0", bd.EntropyBonus)
	}
}

// Entropy alone is not evidence: smali text sits at ~5.1 bits/byte across the
// board, so a zero-match file must not receive the bonus that manufactured
// the "Unknown, 0 matches" hotspots.
func TestScoreFile_HighEntropyWithoutMatchesNoBonus(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/Config.smali", true, 5)
	a.Entropy = 7.5

	bd := s.ScoreFileDetailed(a)
	if bd.EntropyBonus != 0 {
		t.Errorf("EntropyBonus = %f, want 0 (no matches to corroborate)", bd.EntropyBonus)
	}
}

func TestScoreFile_HighEntropyWithCritical(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/License.smali", true, 5)
	addMatch(a, types.CategoryLicenseCheck)
	a.Entropy = 7.5

	bd := s.ScoreFileDetailed(a)
	if bd.EntropyBonus != DefaultWeights.EntropyCriticalBoost {
		t.Errorf("EntropyBonus = %f, want %f (critical boost)",
			bd.EntropyBonus, DefaultWeights.EntropyCriticalBoost)
	}
}

func TestScoreFile_SuspiciousMethods(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/Check.smali", true, 5)
	// Suspicious-method bonus now only applies alongside a real signal.
	addMatch(a, types.CategoryLicenseCheck)
	a.SuspiciousScore = 50.0

	bd := s.ScoreFileDetailed(a)
	if bd.SuspiciousBonus <= 0 {
		t.Errorf("SuspiciousBonus = %f, want > 0", bd.SuspiciousBonus)
	}
}

func TestScoreFile_NonCriticalMatches(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/Utils.smali", true, 3)
	for i := 0; i < 10; i++ {
		addMatch(a, types.CategoryAnalytics)
	}

	bd := s.ScoreFileDetailed(a)
	if bd.NonCriticalBonus <= 0 {
		t.Errorf("NonCriticalBonus = %f, want > 0", bd.NonCriticalBonus)
	}
}

// ============================================================================
// ScoreFileDetailed Breakdown
// ============================================================================

func TestScoreFileDetailed_AllComponents(t *testing.T) {
	s := newTestScorer()
	a := newTestAnalysis("smali/com/app/Premium.smali", true, 9)

	addMatch(a, types.CategoryLicenseCheck)
	addMatch(a, types.CategoryBillingClient) // inventory, not critical
	addMatch(a, types.CategoryAnalytics)
	addMatch(a, types.CategoryAdNetwork)
	// Second genuinely critical category: billing no longer qualifies, so the
	// CriticalCount>=2 assertion needs a real critical signal next to the
	// license check.
	addMatch(a, types.CategorySignatureCheck)

	a.DecisionPoints = []types.DecisionPoint{
		{Method: "isPremium", Type: types.DecisionBooleanReturn},
		{Method: "checkLicense", Type: types.DecisionCallback},
	}
	a.Entropy = 6.0
	a.SuspiciousScore = 20.0

	bd := s.ScoreFileDetailed(a)

	if bd.BaseScore <= 0 {
		t.Errorf("BaseScore = %f", bd.BaseScore)
	}
	if bd.CriticalBonus <= 0 {
		t.Errorf("CriticalBonus = %f", bd.CriticalBonus)
	}
	if bd.DecisionBonus <= 0 {
		t.Errorf("DecisionBonus = %f", bd.DecisionBonus)
	}
	if bd.RawTotal <= 0 {
		t.Errorf("RawTotal = %f", bd.RawTotal)
	}
	if bd.NormalizedTotal <= 0 {
		t.Errorf("NormalizedTotal = %f", bd.NormalizedTotal)
	}
	if bd.CriticalCount < 2 {
		t.Errorf("CriticalCount = %d", bd.CriticalCount)
	}
	if bd.UniqueCategories < 2 {
		t.Errorf("UniqueCategories = %d", bd.UniqueCategories)
	}
}

// ============================================================================
// CalculateHotspots
// ============================================================================

func TestCalculateHotspots_Empty(t *testing.T) {
	s := newTestScorer()
	hotspots := s.CalculateHotspots(nil, 10)
	if len(hotspots) != 0 {
		t.Errorf("expected 0 hotspots, got %d", len(hotspots))
	}
}

func TestCalculateHotspots_FiltersLibrary(t *testing.T) {
	s := newTestScorer()
	files := map[string]*types.FileAnalysis{
		"smali/android/app/Activity.smali": newTestAnalysis("smali/android/app/Activity.smali", false, 1),
	}
	hotspots := s.CalculateHotspots(files, 10)
	if len(hotspots) != 0 {
		t.Errorf("expected 0 hotspots for library, got %d", len(hotspots))
	}
}

func TestCalculateHotspots_Ranking(t *testing.T) {
	s := newTestScorer()
	files := make(map[string]*types.FileAnalysis)

	high := newTestAnalysis("smali/com/app/License.smali", true, 9)
	addMatch(high, types.CategoryLicenseCheck)
	addMatch(high, types.CategoryLicenseCheck)
	addMatch(high, types.CategoryBillingClient)
	high.DecisionPoints = append(high.DecisionPoints, types.DecisionPoint{
		Method: "check", Type: types.DecisionBooleanReturn,
	})
	files["smali/com/app/License.smali"] = high

	low := newTestAnalysis("smali/com/app/Utils.smali", true, 2)
	addMatch(low, types.CategoryAnalytics)
	files["smali/com/app/Utils.smali"] = low

	hotspots := s.CalculateHotspots(files, 10)

	if len(hotspots) == 0 {
		t.Fatal("expected hotspots")
	}
	if hotspots[0].Path != "smali/com/app/License.smali" {
		t.Errorf("first hotspot = %q, want License", hotspots[0].Path)
	}
}

func TestCalculateHotspots_TopNLimit(t *testing.T) {
	s := newTestScorer()
	files := make(map[string]*types.FileAnalysis)

	for i := 0; i < 100; i++ {
		path := "smali/com/app/File" + string(rune('A'+i%26)) + ".smali"
		a := newTestAnalysis(path, true, 5)
		addMatch(a, types.CategoryLicenseCheck)
		files[path] = a
	}

	hotspots := s.CalculateHotspots(files, 5)
	if len(hotspots) > 5 {
		t.Errorf("expected max 5 hotspots, got %d", len(hotspots))
	}
}

func TestCalculateHotspots_DefaultTopN(t *testing.T) {
	s := newTestScorer()
	hotspots := s.CalculateHotspots(map[string]*types.FileAnalysis{}, 0)
	if hotspots == nil {
		t.Error("expected non-nil slice")
	}
}

// ============================================================================
// normalize
// ============================================================================

func TestNormalize(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		cap   float64
	}{
		{"below cap", 50, 100},
		{"at cap", 100, 100},
		{"above cap", 200, 100},
		{"way above", 1000, 100},
		{"zero cap", 50, 0},
		{"zero score", 0, 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalize(tc.score, tc.cap)

			if tc.cap <= 0 {
				if result != tc.score {
					t.Errorf("with cap=0: result=%f, want %f", result, tc.score)
				}
				return
			}
			if tc.score <= tc.cap {
				if result != tc.score {
					t.Errorf("below cap: result=%f, want %f", result, tc.score)
				}
			} else {
				if result <= tc.cap {
					t.Errorf("above cap: result=%f should be > cap=%f", result, tc.cap)
				}
				if result >= tc.score {
					t.Errorf("above cap: result=%f should be < raw=%f", result, tc.score)
				}
			}
		})
	}
}

// ============================================================================
// appendReason
// ============================================================================

func TestAppendReason(t *testing.T) {
	var reasons []string
	for i := 0; i < maxReasons+5; i++ {
		reasons = appendReason(reasons, "reason")
	}
	if len(reasons) != maxReasons {
		t.Errorf("len = %d, want %d", len(reasons), maxReasons)
	}
}

// ============================================================================
// min
// ============================================================================

func TestMin(t *testing.T) {
	if min(3, 5) != 3 {
		t.Error("min(3,5)")
	}
	if min(5, 3) != 3 {
		t.Error("min(5,3)")
	}
	if min(3, 3) != 3 {
		t.Error("min(3,3)")
	}
}

// ============================================================================
// sortHotspots
// ============================================================================

func TestSortHotspots(t *testing.T) {
	hotspots := []types.Hotspot{
		{Path: "c.smali", Score: 50, CriticalCount: 0},
		{Path: "a.smali", Score: 100, CriticalCount: 2},
		{Path: "b.smali", Score: 80, CriticalCount: 1},
	}

	sortHotspots(hotspots)

	if hotspots[0].Path != "a.smali" {
		t.Errorf("first = %q, want a.smali", hotspots[0].Path)
	}
	if hotspots[1].Path != "b.smali" {
		t.Errorf("second = %q, want b.smali", hotspots[1].Path)
	}
}

func TestSortHotspots_TieBreaking(t *testing.T) {
	hotspots := []types.Hotspot{
		{Path: "b.smali", Score: 100, CriticalCount: 1},
		{Path: "a.smali", Score: 100, CriticalCount: 1},
	}

	sortHotspots(hotspots)

	if hotspots[0].Path != "a.smali" {
		t.Errorf("first = %q, want a.smali", hotspots[0].Path)
	}
}

// ============================================================================
// getCategoryInfo cache
// ============================================================================

func TestGetCategoryInfo_Cache(t *testing.T) {
	s := newTestScorer()
	info1 := s.getCategoryInfo(types.CategoryLicenseCheck)
	info2 := s.getCategoryInfo(types.CategoryLicenseCheck)
	if info1.Name != info2.Name {
		t.Error("cached result should match")
	}
}

// ============================================================================
// uniqueCategories
// ============================================================================

func TestUniqueCategories(t *testing.T) {
	s := newTestScorer()
	matches := []types.Match{
		{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
		{Categorized: types.Categorized{Category: types.CategoryAnalytics}},
		{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}},
		{Categorized: types.Categorized{Category: types.CategoryBillingClient}},
	}

	cats := s.uniqueCategories(matches)
	if len(cats) != 3 {
		t.Errorf("unique categories = %d, want 3", len(cats))
	}
}
