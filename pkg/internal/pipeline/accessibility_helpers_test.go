package pipeline

import (
	"math"
	"testing"
)

func TestSigmoid(t *testing.T) {
	if got := sigmoid(0); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("sigmoid(0) = %v, want 0.5", got)
	}
	if got := sigmoid(10); got <= 0.99 {
		t.Errorf("sigmoid(10) = %v, want > 0.99", got)
	}
	if got := sigmoid(-10); got >= 0.01 {
		t.Errorf("sigmoid(-10) = %v, want < 0.01", got)
	}
}

func TestCalculateThreatScoreNoService(t *testing.T) {
	s := newAccessibilityState()
	if got := s.calculateThreatScore(); got != 0 {
		t.Errorf("threat score without accessibility service should be 0, got %v", got)
	}
}

func TestCalculateThreatScoreWithService(t *testing.T) {
	s := newAccessibilityState()
	s.hasAccessibilityService = true
	s.hasAccessibilitySubclass = true // capability rule: binding + real subclass
	if got := s.calculateThreatScore(); got <= 0 || got > 10 {
		t.Errorf("base threat score out of range: %v", got)
	}

	// A binding without an AccessibilityService subclass is not a capability.
	bindingOnly := newAccessibilityState()
	bindingOnly.hasAccessibilityService = true
	if got := bindingOnly.calculateThreatScore(); got != 0 {
		t.Errorf("binding without subclass should score 0, got %v", got)
	}

	s.hasSystemAlertWindow = true
	s.hasDeviceAdmin = true
	s.hasSMSPermissions = true
	s.hasFinancialKeywords = true
	s.clickSimulations = 5
	s.keylogHits = 3
	got := s.calculateThreatScore()
	if got <= 0 || got > 10 {
		t.Errorf("populated threat score out of range: %v", got)
	}
}

func TestPermissionRiskNormalized(t *testing.T) {
	s := newAccessibilityState()
	if got := s.permissionRiskNormalized(); got != 0 {
		t.Error("no service should yield 0")
	}

	s.hasAccessibilityService = true
	if got := s.permissionRiskNormalized(); got != 0 {
		t.Error("service alone should yield 0 (no permissions)")
	}

	s.hasSystemAlertWindow = true
	s.hasDeviceAdmin = true
	s.hasSMSPermissions = true
	got := s.permissionRiskNormalized()
	if got <= 0 || got > 1 {
		t.Errorf("permission risk should be in (0,1], got %v", got)
	}

	// 6+ permissions should saturate at 1.
	s.hasNotificationAccess = true
	s.hasInstallPackages = true
	s.hasBootReceiver = true
	s.hasKeyguardDisable = true
	s.hasUsageStats = true
	s.hasCamera = true
	if got := s.permissionRiskNormalized(); got != 1.0 {
		t.Errorf("6+ permissions should saturate, got %v", got)
	}
}

func TestContextRiskNormalized(t *testing.T) {
	s := newAccessibilityState()
	if got := s.contextRiskNormalized(); got != 0 {
		t.Errorf("empty context should be 0, got %v", got)
	}

	s.hasFinancialKeywords = true
	s.hasCryptoKeywords = true
	s.hasCredentialPattern = true
	s.hasGeoTargeting = true
	if got := s.contextRiskNormalized(); got < 0.99 {
		t.Errorf("all flags should saturate near 1, got %v", got)
	}
}

func TestAccessibilityDetectorName(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	if got := d.Name(); got == "" {
		t.Error("Name should be non-empty")
	}
}

func TestAccessibilityDetectorReset(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	// Mutate some flags and call Reset.
	d.state.hasAccessibilityService = true
	d.state.clickSimulations = 99
	d.state.threats["x"] = &AccessibilityThreat{}
	d.Reset()
	if d.state.hasAccessibilityService {
		t.Error("Reset should clear hasAccessibilityService")
	}
	if d.state.clickSimulations != 0 {
		t.Error("Reset should clear counters")
	}
	if len(d.state.threats) != 0 {
		t.Error("Reset should clear threats map")
	}
}

func TestAccessibilityGetters(t *testing.T) {
	d := NewAccessibilityAbuseDetector()
	d.state.hasAccessibilityService = true
	d.state.hasSystemAlertWindow = true
	d.state.hasDeviceAdmin = true

	threats := d.GetThreats()
	_ = threats // may be nil/empty; we only exercise the method

	if got := d.GetMaxThreatLevel(); got < 0 {
		t.Errorf("GetMaxThreatLevel should be ≥0, got %d", got)
	}
	if got := d.GetMaxThreatScore(); got < 0 || got > 10 {
		t.Errorf("GetMaxThreatScore out of range: %v", got)
	}
	signals := d.GetMLSignals()
	_ = signals
	risk := d.GetRiskSignals()
	_ = risk
}
