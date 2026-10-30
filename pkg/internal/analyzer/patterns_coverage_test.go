package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestPatterns_Match(t *testing.T) {
	analyzer := NewDefaultMethodAnalyzer()
	class := &types.SmaliClass{Name: "com.test.Core"}

	// 1. matchLicenseCheckBypass
	mLicense := &types.SmaliMethod{
		Name:           "isLicensed",
		ReturnsBoolean: true,
		Conditions:     []types.Condition{{}},
	}
	matches := analyzer.matchPatterns(mLicense, class)
	if !hasPattern(matches, "license_check_bypass") {
		t.Error("Should match license_check_bypass")
	}

	// 2. matchRootDetection
	mRoot := &types.SmaliMethod{
		Name:         "checkSu",
		StringConsts: []types.StringConstant{{Value: "/system/xbin/su"}},
	}
	matches = analyzer.matchPatterns(mRoot, class)
	if !hasPattern(matches, "root_detection") {
		t.Error("Should match root_detection")
	}

	// 3. matchEmulatorDetection
	mEmu := &types.SmaliMethod{
		Name:          "isEmulator",
		StringConsts:  []types.StringConstant{{Value: "google_sdk"}},
		FieldAccesses: []types.FieldAccess{{Class: "android/os/Build", Field: "MODEL"}},
	}
	matches = analyzer.matchPatterns(mEmu, class)
	if !hasPattern(matches, "emulator_detection") {
		t.Error("Should match emulator_detection")
	}

	// 4. matchDebugDetection
	mDebug := &types.SmaliMethod{
		Name:          "test",
		Invokes:       []types.Invoke{{Method: "isDebuggerConnected"}},
		FieldAccesses: []types.FieldAccess{{Class: "ApplicationInfo", Field: "flags"}},
	}
	matches = analyzer.matchPatterns(mDebug, class)
	if !hasPattern(matches, "debug_detection") {
		t.Error("Should match debug_detection")
	}

	// 5. matchSSLPinning
	mSSL := &types.SmaliMethod{
		Name:         "test",
		Invokes:      []types.Invoke{{Class: "TrustManager", Method: "checkServerTrusted"}},
		StringConsts: []types.StringConstant{{Value: "sha256/12345"}},
	}
	matches = analyzer.matchPatterns(mSSL, class)
	if !hasPattern(matches, "ssl_pinning") {
		t.Error("Should match ssl_pinning")
	}

	// 6. matchTrialExpiry
	mTrial := &types.SmaliMethod{
		Name:         "test", // trial check
		Invokes:      []types.Invoke{{Method: "currentTimeMillis"}},
		StringConsts: []types.StringConstant{{Value: "trial expired"}},
	}
	matches = analyzer.matchPatterns(mTrial, class)
	if !hasPattern(matches, "trial_expiry") {
		t.Error("Should match trial_expiry")
	}

	// 7. matchSignatureVerification
	mSig := &types.SmaliMethod{
		Name: "test",
		Invokes: []types.Invoke{
			{Method: "checkSignatures"},
			{Class: "MessageDigest"},
		},
	}
	matches = analyzer.matchPatterns(mSig, class)
	if !hasPattern(matches, "signature_verification") {
		t.Error("Should match signature_verification")
	}

	// 8. matchSimpleBooleanGate
	mGate := &types.SmaliMethod{
		Name:           "isFeatureEnabled",
		ReturnsBoolean: true,
		Metrics:        types.MethodMetrics{InstructionCount: 5},
		Instructions: []types.Instruction{
			{Opcode: "const/4"},
			{Opcode: "return"},
		},
	}
	matches = analyzer.matchPatterns(mGate, class)
	if !hasPattern(matches, "simple_boolean_gate") {
		t.Error("Should match simple_boolean_gate")
	}

	// 9. matchFeatureFlagCheck
	mFlag := &types.SmaliMethod{
		Name:           "toggleFeature",
		ReturnsBoolean: true,
	}
	matches = analyzer.matchPatterns(mFlag, class)
	if !hasPattern(matches, "feature_flag_check") {
		t.Error("Should match feature_flag_check")
	}
}

func hasPattern(matches []types.PatternMatch, id string) bool {
	for _, m := range matches {
		if m.PatternID == id {
			return true
		}
	}
	return false
}
