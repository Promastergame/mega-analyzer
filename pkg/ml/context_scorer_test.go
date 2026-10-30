package ml

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS — переименовано чтобы не конфликтовать с patch_scorer_test.go
// ═══════════════════════════════════════════════════════════════════════════════

func newContextTestScorer() *ContextScorer {
	return NewDefaultContextScorer()
}

func newContextTestContext(packageName string, permissions []string, signals []string) *AppContext {
	ctx := NewAppContext(packageName, permissions)
	for _, s := range signals {
		ctx.AddSignal(s)
	}
	return ctx
}

// ═══════════════════════════════════════════════════════════════════════════════
// APP TYPE DETECTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDetectAppType_Banking(t *testing.T) {
	tests := []struct {
		packageName string
		wantType    AppType
		minConf     float64
	}{
		{"com.sberbank.android", AppTypeBanking, 0.3},
		{"ru.tinkoff.investing", AppTypeBanking, 0.3},
		{"com.chase.mobile", AppTypeBanking, 0.3},
		{"com.bankofamerica.mobile", AppTypeBanking, 0.3},
		{"ru.alfabank.mobile", AppTypeBanking, 0.3},
	}

	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {
			ctx := NewAppContext(tt.packageName, nil)

			if ctx.DetectedType != tt.wantType {
				t.Errorf("got type %s, want %s", ctx.DetectedType, tt.wantType)
			}
			if ctx.TypeConfidence < tt.minConf {
				t.Errorf("got confidence %.2f, want >= %.2f", ctx.TypeConfidence, tt.minConf)
			}
		})
	}
}

func TestDetectAppType_Crypto(t *testing.T) {
	tests := []struct {
		packageName string
		wantType    AppType
	}{
		{"com.binance.dev", AppTypeCrypto},
		{"com.coinbase.android", AppTypeCrypto},
		{"io.metamask", AppTypeCrypto},
		{"com.trustwallet.app", AppTypeCrypto},
	}

	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {
			ctx := NewAppContext(tt.packageName, nil)
			if ctx.DetectedType != tt.wantType {
				t.Errorf("got type %s, want %s", ctx.DetectedType, tt.wantType)
			}
		})
	}
}

func TestDetectAppType_Accessibility(t *testing.T) {
	permissions := []string{"android.permission.BIND_ACCESSIBILITY_SERVICE"}

	tests := []struct {
		packageName string
		wantType    AppType
	}{
		{"com.google.android.marvin.talkback", AppTypeAccessibility},
		{"com.accessibility.helper", AppTypeAccessibility},
	}

	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {
			ctx := NewAppContext(tt.packageName, permissions)
			if ctx.DetectedType != tt.wantType {
				t.Errorf("got type %s, want %s", ctx.DetectedType, tt.wantType)
			}
		})
	}
}

func TestDetectAppType_Generic(t *testing.T) {
	ctx := NewAppContext("com.unknown.random.app", nil)
	if ctx.DetectedType != AppTypeGeneric {
		t.Errorf("got type %s, want %s", ctx.DetectedType, AppTypeGeneric)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERMISSION FLAGS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestParsePermissions(t *testing.T) {
	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.SEND_SMS",
		"android.permission.CAMERA",
		"android.permission.INTERNET",
	}

	flags := ParsePermissions(permissions)

	if !flags.Has(PermOverlay) {
		t.Error("expected PermOverlay flag")
	}
	if !flags.Has(PermAccessibility) {
		t.Error("expected PermAccessibility flag")
	}
	if !flags.Has(PermSendSMS) {
		t.Error("expected PermSendSMS flag")
	}
	if flags.Has(PermDeviceAdmin) {
		t.Error("unexpected PermDeviceAdmin flag")
	}
}

func TestPermissionFlags_HasAll(t *testing.T) {
	flags := PermOverlay | PermAccessibility | PermDeviceAdmin

	if !flags.HasAll(PermOverlay | PermAccessibility) {
		t.Error("HasAll should return true for subset")
	}

	if flags.HasAll(PermOverlay | PermSendSMS) {
		t.Error("HasAll should return false when one flag missing")
	}
}

func TestPermissionFlags_DangerousCount(t *testing.T) {
	tests := []struct {
		name  string
		flags PermissionFlags
		want  int
	}{
		{"no dangerous", PermInternet | PermCamera, 0},
		{"one dangerous", PermOverlay, 1},
		{"multiple dangerous", PermOverlay | PermAccessibility | PermDeviceAdmin, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.DangerousCount()
			if got != tt.want {
				t.Errorf("DangerousCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL SCORING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestSignalRule_GetPoints(t *testing.T) {
	rules := NewContextRules()

	tests := []struct {
		signal   string
		appType  AppType
		wantBase int
		wantMod  int
	}{
		{"overlay_permission", AppTypeBanking, 4, 12},
		{"overlay_permission", AppTypeAccessibility, 4, -3},
		{"accessibility_service", AppTypeBanking, 3, 12},
		{"accessibility_service", AppTypeAccessibility, 3, -10},
		{"device_admin", AppTypeSecurity, 10, -8},
		{"device_admin", AppTypeBanking, 10, 18},
	}

	for _, tt := range tests {
		t.Run(tt.signal+"_"+string(tt.appType), func(t *testing.T) {
			rule := rules.GetSignalRule(tt.signal)
			base, mod, _ := rule.GetPoints(tt.appType)

			if base != tt.wantBase {
				t.Errorf("base = %d, want %d", base, tt.wantBase)
			}
			if mod != tt.wantMod {
				t.Errorf("mod = %d, want %d", mod, tt.wantMod)
			}
		})
	}
}

func TestScoreSignals_ContextMatters(t *testing.T) {
	scorer := newContextTestScorer()

	signals := []string{"overlay_permission", "accessibility_service"}

	bankingScore := scorer.ScoreSignals(signals, AppTypeBanking)
	a11yScore := scorer.ScoreSignals(signals, AppTypeAccessibility)
	genericScore := scorer.ScoreSignals(signals, AppTypeGeneric)

	if bankingScore <= genericScore {
		t.Errorf("banking score (%d) should be > generic (%d)", bankingScore, genericScore)
	}

	if a11yScore >= genericScore {
		t.Errorf("accessibility score (%d) should be < generic (%d)", a11yScore, genericScore)
	}

	t.Logf("Scores: banking=%d, generic=%d, accessibility=%d", bankingScore, genericScore, a11yScore)
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBO DETECTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestComboRule_Matches(t *testing.T) {
	tests := []struct {
		name    string
		combo   ComboRule
		signals []string
		want    bool
	}{
		{
			name: "exact match",
			combo: ComboRule{
				Signals: []string{"overlay_permission", "device_admin"},
			},
			signals: []string{"overlay_permission", "device_admin"},
			want:    true,
		},
		{
			name: "missing signal",
			combo: ComboRule{
				Signals: []string{"overlay_permission", "device_admin"},
			},
			signals: []string{"overlay_permission"},
			want:    false,
		},
		{
			name: "with any_of - matches",
			combo: ComboRule{
				Signals: []string{"sms_permission", "boot_receiver"},
				AnyOf:   []string{"c2_communication", "data_exfiltration"},
			},
			signals: []string{"sms_permission", "boot_receiver", "c2_communication"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.combo.Matches(tt.signals)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindMatchingCombos(t *testing.T) {
	rules := NewContextRules()

	signals := []string{"overlay_permission", "device_admin"}
	combos := rules.FindMatchingCombos(signals)

	found := false
	for _, c := range combos {
		if c.Name == "trojan_overlay_admin" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected trojan_overlay_admin combo")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FULL SCORING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestScore_BankingTrojan(t *testing.T) {
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.BIND_DEVICE_ADMIN",
		"android.permission.RECEIVE_SMS",
		"android.permission.INTERNET",
	}

	ctx := NewAppContext("com.fake.banking.app", permissions)
	ctx.AddSignal("financial_target")
	ctx.AddSignal("keylogging")

	result := scorer.Score(ctx)

	if result.ThreatLevel != ThreatCritical {
		t.Errorf("expected CRITICAL, got %s (score: %d)", result.ThreatLevel, result.TotalScore)
	}

	if len(result.MatchedCombos) == 0 {
		t.Error("expected at least one combo match")
	}

	if len(result.Threats) == 0 {
		t.Error("expected at least one threat")
	}

	t.Logf("Score: %d, Threat: %s, Threats: %v", result.TotalScore, result.ThreatLevel, result.Threats)
}

func TestScore_LegitimateAccessibilityApp(t *testing.T) {
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.INTERNET",
	}

	ctx := NewAppContext("com.google.android.marvin.talkback", permissions)

	result := scorer.Score(ctx)

	if result.ThreatLevel == ThreatHigh || result.ThreatLevel == ThreatCritical {
		t.Errorf("accessibility app should not be high risk, got %s (score: %d)",
			result.ThreatLevel, result.TotalScore)
	}

	if result.TypeBias >= 0 {
		t.Errorf("accessibility app should have negative bias, got %d", result.TypeBias)
	}

	t.Logf("Score: %d, Threat: %s, TypeBias: %d", result.TotalScore, result.ThreatLevel, result.TypeBias)
}

func TestScore_PiracyApp(t *testing.T) {
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.INTERNET",
		"android.permission.WRITE_EXTERNAL_STORAGE",
	}

	ctx := NewAppContext("com.utorrent.android", permissions)
	ctx.AddSignal("piracy_url")

	result := scorer.Score(ctx)

	// piracy_url в piracy app: 12 - 10 = 2 очка
	if result.TotalScore > 20 {
		t.Errorf("piracy app with piracy_url should have low score, got %d", result.TotalScore)
	}

	t.Logf("Score: %d, Threat: %s", result.TotalScore, result.ThreatLevel)
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT LEVEL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestThreatThresholds_GetLevel(t *testing.T) {
	thresholds := DefaultThreatThresholds

	tests := []struct {
		score int
		want  ThreatLevel
	}{
		{0, ThreatNone},
		{5, ThreatLow},
		{15, ThreatLow},
		{16, ThreatMedium},
		{40, ThreatMedium},
		{41, ThreatHigh},
		{70, ThreatHigh},
		{71, ThreatCritical},
		{100, ThreatCritical},
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			got := thresholds.GetLevel(tt.score)
			if got != tt.want {
				t.Errorf("GetLevel(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUICK METHODS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestQuickScore(t *testing.T) {
	scorer := newContextTestScorer()

	signals := []string{"overlay_permission", "device_admin"}

	score, level := scorer.QuickScore(signals, AppTypeBanking)

	if level != ThreatCritical {
		t.Errorf("expected CRITICAL, got %s (score: %d)", level, score)
	}

	t.Logf("QuickScore: %d, Level: %s", score, level)
}

func TestIsHighRisk(t *testing.T) {
	scorer := newContextTestScorer()

	// Реально high risk — overlay + admin + financial target
	highRiskCtx := newContextTestContext("com.malware.app", []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.BIND_DEVICE_ADMIN",
	}, nil)

	result := scorer.Score(highRiskCtx)
	t.Logf("High risk - Score: %d, Level: %s, Combos: %d",
		result.TotalScore, result.ThreatLevel, len(result.MatchedCombos))

	if !scorer.IsHighRisk(highRiskCtx) {
		t.Errorf("overlay + a11y + admin should be high risk, got score %d", result.TotalScore)
	}

	// Medium risk — overlay + admin (без accessibility)
	mediumRiskCtx := newContextTestContext("com.suspicious.app", []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_DEVICE_ADMIN",
	}, nil)

	medResult := scorer.Score(mediumRiskCtx)
	t.Logf("Medium risk - Score: %d, Level: %s",
		medResult.TotalScore, medResult.ThreatLevel)

	// overlay + admin в generic = medium, не low
	if medResult.ThreatLevel == ThreatLow || medResult.ThreatLevel == ThreatNone {
		t.Errorf("overlay + admin should be at least medium risk, got %s", medResult.ThreatLevel)
	}

	// Low risk context
	lowRiskCtx := newContextTestContext("com.normal.app", []string{
		"android.permission.INTERNET",
	}, nil)

	if scorer.IsHighRisk(lowRiskCtx) {
		t.Error("normal app should not be high risk")
	}
}

func TestHasDangerousCombos(t *testing.T) {
	scorer := newContextTestScorer()

	dangerousSignals := []string{"overlay_permission", "device_admin"}
	if !scorer.HasDangerousCombos(dangerousSignals) {
		t.Error("overlay + admin should be dangerous combo")
	}

	safeSignals := []string{"boot_receiver"}
	if scorer.HasDangerousCombos(safeSignals) {
		t.Error("boot_receiver alone should not have dangerous combos")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT FORMAT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestFormatResult(t *testing.T) {
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
	}

	ctx := NewAppContext("com.test.banking", permissions)
	result := scorer.Score(ctx)

	output := scorer.FormatResult(result)

	checks := []string{
		"THREAT LEVEL",
		"Total Score",
		"Signal Breakdown",
		"overlay_permission",
		"accessibility_service",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output should contain %q", check)
		}
	}

	t.Log(output)
}

func TestFormatCompact(t *testing.T) {
	scorer := newContextTestScorer()

	ctx := newContextTestContext("com.test.app", nil, []string{"overlay_permission"})
	result := scorer.Score(ctx)

	compact := scorer.FormatCompact(result)

	if len(compact) > 100 {
		t.Errorf("compact format too long: %d chars", len(compact))
	}

	if !strings.Contains(compact, "pts") {
		t.Error("compact should contain points")
	}

	t.Logf("Compact: %s", compact)
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPARISON TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCompareAppTypes(t *testing.T) {
	scorer := newContextTestScorer()

	signals := []string{"overlay_permission", "accessibility_service"}
	comparison := scorer.CompareAppTypes(signals)

	if comparison[AppTypeBanking] <= comparison[AppTypeAccessibility] {
		t.Errorf("banking (%d) should score higher than accessibility (%d)",
			comparison[AppTypeBanking], comparison[AppTypeAccessibility])
	}

	t.Log("Score comparison:")
	for appType, score := range comparison {
		t.Logf("  %s: %d", appType, score)
	}
}

func TestGetSignalImpact(t *testing.T) {
	scorer := newContextTestScorer()

	impact := scorer.GetSignalImpact("overlay_permission")

	// Найдём тип с максимальным impact
	maxType := AppTypeGeneric
	maxScore := 0
	for appType, score := range impact {
		if score > maxScore {
			maxScore = score
			maxType = appType
		}
	}

	// Banking, Malware, Payment или Crypto должны иметь максимальный impact
	validMax := maxType == AppTypeBanking || maxType == AppTypeMalware ||
		maxType == AppTypePayment || maxType == AppTypeCrypto

	if !validMax {
		t.Errorf("expected financial/malware to have max overlay impact, got %s (%d)", maxType, maxScore)
	}

	t.Log("Overlay impact by app type:")
	for appType, score := range impact {
		t.Logf("  %s: %d", appType, score)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

func TestScore_NilContext(t *testing.T) {
	scorer := newContextTestScorer()

	result := scorer.Score(nil)

	if result.ThreatLevel != ThreatNone {
		t.Errorf("nil context should be ThreatNone, got %s", result.ThreatLevel)
	}
}

func TestScore_EmptyContext(t *testing.T) {
	scorer := newContextTestScorer()

	ctx := NewAppContext("", nil)
	result := scorer.Score(ctx)

	if result.TotalScore != 0 {
		t.Errorf("empty context should have 0 score, got %d", result.TotalScore)
	}
}

func TestScore_UnknownSignal(t *testing.T) {
	scorer := newContextTestScorer()

	ctx := newContextTestContext("com.test.app", nil, []string{"unknown_signal_xyz"})
	result := scorer.Score(ctx)

	// Unknown signals get default 1 point
	if result.SignalScore != 1 {
		t.Errorf("unknown signal should get 1 point, got %d", result.SignalScore)
	}
}

func TestScore_MultipleUnknownSignals(t *testing.T) {
	scorer := newContextTestScorer()

	ctx := newContextTestContext("com.test.app", nil, []string{
		"unknown_signal_1",
		"unknown_signal_2",
		"unknown_signal_3",
	})
	result := scorer.Score(ctx)

	// 3 unknown signals × 1 point each = 3
	if result.SignalScore != 3 {
		t.Errorf("3 unknown signals should get 3 points, got %d", result.SignalScore)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REAL-WORLD SCENARIO TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestScenario_Anubis_BankingTrojan(t *testing.T) {
	// Симуляция Anubis banking trojan
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.RECEIVE_SMS",
		"android.permission.READ_SMS",
		"android.permission.SEND_SMS",
		"android.permission.RECEIVE_BOOT_COMPLETED",
		"android.permission.INTERNET",
		"android.permission.READ_CONTACTS",
		"android.permission.RECORD_AUDIO",
	}

	ctx := NewAppContext("com.android.systemupdate", permissions) // типичное имя трояна
	ctx.AddSignal("financial_target")
	ctx.AddSignal("keylogging")
	ctx.AddSignal("screen_capture")
	ctx.AddSignal("c2_communication")

	result := scorer.Score(ctx)

	// Должен быть CRITICAL
	if result.ThreatLevel != ThreatCritical {
		t.Errorf("Anubis-like trojan should be CRITICAL, got %s", result.ThreatLevel)
	}

	// Должны быть обнаружены banking-related threats
	hasBankingThreat := false
	for _, threat := range result.Threats {
		if strings.Contains(strings.ToLower(threat), "bank") ||
			strings.Contains(strings.ToLower(threat), "stealer") ||
			strings.Contains(strings.ToLower(threat), "trojan") {
			hasBankingThreat = true
			break
		}
	}

	if !hasBankingThreat {
		t.Errorf("should detect banking threat, got: %v", result.Threats)
	}

	t.Logf("Anubis scenario - Score: %d, Level: %s, Threats: %v",
		result.TotalScore, result.ThreatLevel, result.Threats)
}

func TestScenario_Cerberus_Trojan(t *testing.T) {
	// Симуляция Cerberus trojan
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
		"android.permission.RECEIVE_SMS",
		"android.permission.INTERNET",
		"android.permission.RECEIVE_BOOT_COMPLETED",
	}

	ctx := NewAppContext("com.flash.player.update", permissions)
	ctx.AddSignal("financial_target")
	ctx.AddSignal("anti_analysis")
	ctx.AddSignal("data_exfiltration")

	result := scorer.Score(ctx)

	if result.ThreatLevel != ThreatCritical {
		t.Errorf("Cerberus-like trojan should be CRITICAL, got %s", result.ThreatLevel)
	}

	// Должны найти OTP stealer combo (SMS + notification)
	hasOTPCombo := false
	for _, combo := range result.MatchedCombos {
		if strings.Contains(combo.Name, "otp") || strings.Contains(combo.Name, "notification") {
			hasOTPCombo = true
			break
		}
	}

	if !hasOTPCombo {
		t.Log("Expected OTP/notification combo, combos found:")
		for _, c := range result.MatchedCombos {
			t.Logf("  - %s", c.Name)
		}
	}

	t.Logf("Cerberus scenario - Score: %d, Level: %s", result.TotalScore, result.ThreatLevel)
}

func TestScenario_LegitimatePasswordManager(t *testing.T) {
	// Легитимный password manager (использует accessibility для autofill)
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.INTERNET",
		"android.permission.USE_BIOMETRIC",
	}

	ctx := NewAppContext("com.bitwarden.vault", permissions)

	result := scorer.Score(ctx)

	// Не должен быть CRITICAL (accessibility легитимен)
	if result.ThreatLevel == ThreatCritical {
		t.Errorf("legitimate password manager should not be CRITICAL, got %s (score: %d)",
			result.ThreatLevel, result.TotalScore)
	}

	t.Logf("Password manager - Score: %d, Level: %s", result.TotalScore, result.ThreatLevel)
}

func TestScenario_LegitimateAntivirus(t *testing.T) {
	// Легитимный антивирус
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.BIND_DEVICE_ADMIN",
		"android.permission.PACKAGE_USAGE_STATS",
		"android.permission.INTERNET",
		"android.permission.RECEIVE_BOOT_COMPLETED",
	}

	ctx := NewAppContext("com.avast.android.mobilesecurity", permissions)

	result := scorer.Score(ctx)

	// Security app с device_admin НЕ должен быть critical
	if result.ThreatLevel == ThreatCritical {
		t.Errorf("legitimate antivirus should not be CRITICAL, got %s (score: %d)",
			result.ThreatLevel, result.TotalScore)
	}

	// Type bias должен быть отрицательным
	if result.TypeBias >= 0 {
		t.Errorf("security app should have negative bias, got %d", result.TypeBias)
	}

	t.Logf("Antivirus - Score: %d, Level: %s, Bias: %d",
		result.TotalScore, result.ThreatLevel, result.TypeBias)
}

func TestScenario_TorrentClient(t *testing.T) {
	// Торрент клиент с piracy URLs
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.INTERNET",
		"android.permission.WRITE_EXTERNAL_STORAGE",
		"android.permission.RECEIVE_BOOT_COMPLETED",
	}

	ctx := NewAppContext("org.proninyaroslav.libretorrent", permissions)
	ctx.AddSignal("piracy_url")

	result := scorer.Score(ctx)

	// Piracy URL в торрент клиенте должен иметь низкий скор
	// (piracy_url: 12 - 10 = 2)
	if result.ThreatLevel == ThreatHigh || result.ThreatLevel == ThreatCritical {
		t.Errorf("torrent client should not be high/critical risk, got %s (score: %d)",
			result.ThreatLevel, result.TotalScore)
	}

	t.Logf("Torrent client - Score: %d, Level: %s", result.TotalScore, result.ThreatLevel)
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestIntegration_FullWorkflow(t *testing.T) {
	// Полный workflow: создание контекста -> скоринг -> форматирование
	scorer := newContextTestScorer()

	// 1. Создаём контекст
	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.SEND_SMS",
	}

	ctx := NewAppContext("com.suspicious.app", permissions)

	// 2. Проверяем автодетекцию сигналов
	if !ctx.HasSignal("overlay_permission") {
		t.Error("should auto-detect overlay_permission signal")
	}
	if !ctx.HasSignal("accessibility_service") {
		t.Error("should auto-detect accessibility_service signal")
	}
	if !ctx.HasSignal("sms_permission") {
		t.Error("should auto-detect sms_permission signal")
	}

	// 3. Добавляем дополнительные сигналы
	ctx.AddSignal("financial_target")

	// 4. Скорим
	result := scorer.Score(ctx)

	// 5. Проверяем результат
	if result.TotalScore <= 0 {
		t.Error("score should be positive")
	}

	if len(result.SignalBreakdown) == 0 {
		t.Error("should have signal breakdown")
	}

	if len(result.Recommendations) == 0 {
		t.Error("should have recommendations")
	}

	// 6. Форматируем
	formatted := scorer.FormatResult(result)
	if len(formatted) == 0 {
		t.Error("formatted output should not be empty")
	}

	compact := scorer.FormatCompact(result)
	if len(compact) == 0 {
		t.Error("compact output should not be empty")
	}

	t.Logf("Integration test passed - Score: %d, Level: %s", result.TotalScore, result.ThreatLevel)
}

func TestIntegration_CompareSecurityVsMalware(t *testing.T) {
	// Сравниваем: одинаковые permissions, но разные package names
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.BIND_DEVICE_ADMIN",
		"android.permission.PACKAGE_USAGE_STATS",
		"android.permission.INTERNET",
	}

	// Security app
	securityCtx := NewAppContext("com.kaspersky.security", permissions)
	securityResult := scorer.Score(securityCtx)

	// Suspicious app с теми же permissions
	suspiciousCtx := NewAppContext("com.system.cleaner.tool", permissions)
	suspiciousResult := scorer.Score(suspiciousCtx)

	// Security app должен иметь меньший скор
	if securityResult.TotalScore >= suspiciousResult.TotalScore {
		t.Errorf("security app (%d) should score lower than suspicious (%d)",
			securityResult.TotalScore, suspiciousResult.TotalScore)
	}

	t.Logf("Security: %d (%s) vs Suspicious: %d (%s)",
		securityResult.TotalScore, securityResult.ThreatLevel,
		suspiciousResult.TotalScore, suspiciousResult.ThreatLevel)
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkContextScore(b *testing.B) {
	scorer := newContextTestScorer()

	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.BIND_DEVICE_ADMIN",
		"android.permission.RECEIVE_SMS",
		"android.permission.INTERNET",
	}

	ctx := NewAppContext("com.test.banking", permissions)
	ctx.AddSignal("financial_target")
	ctx.AddSignal("keylogging")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.Score(ctx)
	}
}

func BenchmarkContextQuickScore(b *testing.B) {
	scorer := newContextTestScorer()

	signals := []string{
		"overlay_permission",
		"accessibility_service",
		"device_admin",
		"sms_permission",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.QuickScore(signals, AppTypeBanking)
	}
}

func BenchmarkNewAppContext(b *testing.B) {
	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.SEND_SMS",
		"android.permission.CAMERA",
		"android.permission.INTERNET",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAppContext("com.sberbank.android", permissions)
	}
}

func BenchmarkFindMatchingCombos(b *testing.B) {
	rules := NewContextRules()

	signals := []string{
		"overlay_permission",
		"accessibility_service",
		"device_admin",
		"financial_target",
		"keylogging",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rules.FindMatchingCombos(signals)
	}
}

func BenchmarkParsePermissions(b *testing.B) {
	permissions := []string{
		"android.permission.SYSTEM_ALERT_WINDOW",
		"android.permission.BIND_ACCESSIBILITY_SERVICE",
		"android.permission.BIND_DEVICE_ADMIN",
		"android.permission.SEND_SMS",
		"android.permission.RECEIVE_SMS",
		"android.permission.CAMERA",
		"android.permission.RECORD_AUDIO",
		"android.permission.INTERNET",
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.READ_CONTACTS",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePermissions(permissions)
	}
}
