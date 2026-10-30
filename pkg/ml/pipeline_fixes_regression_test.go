package ml

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// РЕГРЕССИОННЫЕ ТЕСТЫ: pipeline fixes (feedback → index, substring calls,
// const_replace, final confidence calibration, scan stats)
// ═══════════════════════════════════════════════════════════════════════════════

// TestFeedbackAdjustsLiveIndexWeights — п.1: AdjustIndexedPatternWeights меняет
// живой снапшот индекса, который реально используется скорером, а не
// пакетный реестр VulnerablePatterns (который скоринг не читает).
func TestFeedbackAdjustsLiveIndexWeights(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	patternID := "live_index_weight_pattern"
	for i := 0; i < 4; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	for i := 0; i < 6; i++ {
		tracker.RecordOutcome(patternID, OutcomeFalsePositive)
	}

	idx := BuildPatternIndex()
	idx.AllPatterns = append(idx.AllPatterns, &VulnerablePattern{ID: patternID, Weight: 1.0})

	fi.AdjustIndexedPatternWeights(idx.AllPatterns)

	var found *VulnerablePattern
	for _, vp := range idx.AllPatterns {
		if vp.ID == patternID {
			found = vp
		}
	}
	if found == nil {
		t.Fatal("pattern not found in live index")
	}
	if found.Weight != 0.8 { // precision 0.4 → multiplier 0.8
		t.Errorf("live index weight = %f, expected 0.8", found.Weight)
	}
}

// TestFindCandidates_RequiredCallSubstring — п.2: обфусцированный метод,
// определяемый только по API-вызову (подстрока RequiredCalls в FullCall),
// должен находить кандидата.
func TestFindCandidates_RequiredCallSubstring(t *testing.T) {
	idx := BuildPatternIndex()

	mi := &MethodInfo{
		Name:       "a",
		NameLower:  "a",
		ReturnType: "Z",
		Calls: []CallInfo{
			{
				Type:     "virtual",
				Class:    "Landroid/telephony/TelephonyManager;",
				Method:   "getDeviceId",
				FullCall: "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
			},
		},
	}

	candidates := idx.FindCandidates(mi)
	found := false
	for _, vp := range candidates {
		if vp.ID == "DEVICE_BINDING_ANDROID_ID" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DEVICE_BINDING_ANDROID_ID not found by RequiredCall substring; got %d candidates",
			len(candidates))
	}
}

// TestConstReplace_TargetedReplacement — п.4: const_replace меняет ТОЛЬКО
// строковую константу, сохраняя регистры и структуру метода.
func TestConstReplace_TargetedReplacement(t *testing.T) {
	pg := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:      "getEndpoint",
		MethodSignature: "()Ljava/lang/String;",
		MethodHeader:    ".method public getEndpoint()Ljava/lang/String;",
		MethodBody: []string{
			".method public getEndpoint()Ljava/lang/String;",
			"    .registers 1",
			"    const-string v0, \"https://api.example.com/v1\"",
			"    return-object v0",
			".end method",
		},
	}

	patch := pg.Generate(point)
	if patch == nil {
		t.Fatal("expected a patch")
	}
	if patch.PatchType != PatchConstReplace {
		t.Errorf("PatchType = %s, expected const_replace", patch.PatchType)
	}
	if strings.Contains(patch.PatchedCode, "https://api.example.com/v1") {
		t.Error("original URL should be replaced")
	}
	if !strings.Contains(patch.PatchedCode, "http://YOUR_SERVER/") {
		t.Error("redirect URL should be present")
	}
	if !strings.Contains(patch.PatchedCode, ".registers 1") {
		t.Error("register directive should be preserved")
	}
	if !strings.Contains(patch.PatchedCode, "return-object v0") {
		t.Error("original return should be preserved")
	}
	if !strings.Contains(patch.PatchedCode, ".method public getEndpoint") ||
		!strings.Contains(patch.PatchedCode, ".end method") {
		t.Error("method boundaries should be preserved")
	}
}

// TestConstReplace_FallbackWhenNoExactConst — п.4: если точной const-string
// нет (URL — только префикс длинной строки), smart-патч отбрасывается и
// генератор возвращает валидную обычную заглушку, а не битый код.
func TestConstReplace_FallbackWhenNoExactConst(t *testing.T) {
	pg := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:      "getEndpoint",
		MethodSignature: "()Ljava/lang/String;",
		MethodHeader:    ".method public getEndpoint()Ljava/lang/String;",
		MethodBody: []string{
			".method public getEndpoint()Ljava/lang/String;",
			"    .registers 1",
			"    const-string v0, \"https://api.example.com/v1?key=secret\"",
			"    return-object v0",
			".end method",
		},
	}

	patch := pg.Generate(point)
	if patch == nil {
		t.Fatal("expected fallback patch")
	}
	if !strings.Contains(patch.PatchedCode, "return-object") {
		t.Errorf("fallback should be valid smali for object return; got:\n%s", patch.PatchedCode)
	}
}

// TestFinalizeConfidence_AfterAllSignals — п.5: единая финальная калибровка
// после всех сигналов: score-based confidence, штрафы warnings/library/
// obfuscation, решение auto_patch / needs_review / reject.
func TestFinalizeConfidence_AfterAllSignals(t *testing.T) {
	analyzer := NewPatchAnalyzer()
	scorer := NewPatchScorer(analyzer)

	// 1. Высокий score, app code, без предупреждений → auto_patch.
	point := &PatchPoint{RiskScore: 95}
	scorer.FinalizeConfidence(point, &ScoredMethod{})
	if point.Confidence != 0.95 {
		t.Errorf("confidence = %f, expected 0.95", point.Confidence)
	}
	if point.RuntimeDecision != "auto_patch" {
		t.Errorf("decision = %q, expected auto_patch", point.RuntimeDecision)
	}
	if point.RuntimeConfidence == nil {
		t.Fatal("RuntimeConfidence should be set")
	}
	if point.RuntimeConfidence.NeedsReview {
		t.Error("NeedsReview should be false for 0.95")
	}

	// 2. Три warnings + библиотека → штрафы и needs_review.
	point2 := &PatchPoint{RiskScore: 95, Warnings: []string{"w1", "w2", "w3"}, IsLibraryCode: true}
	scorer.FinalizeConfidence(point2, &ScoredMethod{})
	if point2.Confidence != 0.65 { // 0.95 − 0.15 (warnings) − 0.15 (library)
		t.Errorf("confidence = %f, expected 0.65", point2.Confidence)
	}
	if point2.RuntimeDecision != "needs_review" {
		t.Errorf("decision = %q, expected needs_review", point2.RuntimeDecision)
	}

	// 3. Низкий score → floor MinConfidence 0.3 → reject.
	point3 := &PatchPoint{RiskScore: 10}
	scorer.FinalizeConfidence(point3, &ScoredMethod{})
	if point3.Confidence != 0.3 {
		t.Errorf("confidence = %f, expected floor 0.3", point3.Confidence)
	}
	if point3.RuntimeDecision != "reject" {
		t.Errorf("decision = %q, expected reject", point3.RuntimeDecision)
	}

	// 4. Conformal gate: p < 0.5 → needs_review. Скалер nil, чтобы probability
	// не проходила через сигмоид Платта.
	gateScorer := NewPatchScorer(analyzer)
	gate := NewConformalGate(0.1)
	gate.Calibrate([]float64{0.5}) // threshold = 0.5 → uncertain при p < 0.5
	gateScorer.SetConfidenceCalibration(nil, gate)

	point4 := &PatchPoint{RiskScore: 40}
	gateScorer.FinalizeConfidence(point4, &ScoredMethod{})
	if !point4.RuntimeConfidence.NeedsReview {
		t.Error("conformal gate should flag NeedsReview for 0.4")
	}
	if point4.RuntimeDecision != "needs_review" {
		t.Errorf("decision = %q, expected needs_review", point4.RuntimeDecision)
	}

	// 5. Обфускация → дополнительный штраф 0.05.
	point5 := &PatchPoint{RiskScore: 95}
	scorer.FinalizeConfidence(point5, &ScoredMethod{
		Score: ScoreResult{ObfuscationInfo: &ObfuscationInfo{IsObfuscated: true}},
	})
	if point5.Confidence != 0.90 { // 0.95 − 0.05
		t.Errorf("confidence = %f, expected 0.90", point5.Confidence)
	}
}

// TestCollectSmaliFiles_ScanStats — п.6: пропуски файлов (маленькие, слишком
// большие, ошибки) видны в статистике, лимит размера настраивается.
func TestCollectSmaliFiles_ScanStats(t *testing.T) {
	dir := testTempDir(t)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("tiny.smali", strings.Repeat("x", 50)) // < 100 байт → skipped
	write("ok.smali", strings.Repeat("x", 200))  // нормальный
	write("big.smali", strings.Repeat("x", 900)) // > MaxSmaliFileSize → tooLarge
	write("notes.txt", "not smali")              // не .smali → не считается

	cfg := DefaultPredictorConfig()
	cfg.MaxSmaliFileSize = 600
	pp := NewPatchPredictorWithConfig(io.Discard, cfg)

	candidates, stats, err := pp.collectSmaliFiles(dir)
	if err != nil {
		t.Fatalf("collectSmaliFiles: %v", err)
	}
	if stats.discovered != 3 {
		t.Errorf("discovered = %d, expected 3", stats.discovered)
	}
	if stats.skipped != 2 {
		t.Errorf("skipped = %d, expected 2", stats.skipped)
	}
	if stats.tooLarge != 1 {
		t.Errorf("tooLarge = %d, expected 1", stats.tooLarge)
	}
	if len(candidates) != 1 {
		t.Errorf("candidates = %d, expected 1", len(candidates))
	}

	// Статистика доезжает до PredictionStats через applyFileScanStats.
	prediction := pp.emptyPrediction()
	applyFileScanStats(&prediction.Stats, stats)
	if prediction.Stats.FilesDiscovered != 3 || prediction.Stats.FilesSkipped != 2 ||
		prediction.Stats.FilesTooLarge != 1 {
		t.Errorf("stats not merged: %+v", prediction.Stats)
	}
}
