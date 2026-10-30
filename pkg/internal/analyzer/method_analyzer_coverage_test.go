package analyzer

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestMethodAnalyzer_Analyze_And_Roles(t *testing.T) {
	analyzer := NewDefaultMethodAnalyzer()

	// 1. Checker
	mChecker := &types.SmaliMethod{
		Name:           "isLicenseValid",
		ReturnsBoolean: true,
		Conditions:     []types.Condition{{}},
	}
	class := &types.SmaliClass{Name: "com.test.App"}

	analysis1 := analyzer.Analyze(mChecker, class)
	if !analysis1.FeatureMap["returns_boolean"] || !analysis1.FeatureMap["has_conditions"] {
		t.Error("Features not extracted properly for checker")
	}
	if !analysis1.Flags.IsLicenseRelated() {
		t.Error("Flags not computed properly")
	}

	// 2. Enforcer
	mEnf := &types.SmaliMethod{
		Name: "crash",
		Invokes: []types.Invoke{
			{Class: "Ljava/lang/System;", Method: "exit"},
		},
	}
	a2 := analyzer.Analyze(mEnf, class)
	if !a2.FeatureMap["calls_system_exit"] {
		t.Error("calls_system_exit not detected")
	}

	// 3. Handler
	mHandler := &types.SmaliMethod{
		Name: "onBillingComplete",
		Invokes: []types.Invoke{
			{Class: "Billing", Method: "commit", Tags: []string{"billing"}},
		},
	}
	a3 := analyzer.Analyze(mHandler, class)
	if !a3.FeatureMap["calls_billing_api"] {
		t.Error("calls_billing_api not detected")
	}
	if !a3.Flags.IsBillingRelated() {
		t.Error("Flags not computed properly")
	}

	// 4. Gate / Observer
	mGate := &types.SmaliMethod{
		Name:           "isPro",
		ReturnsBoolean: true,
		Invokes: []types.Invoke{
			{Class: "SharedPreferences", Method: "getBoolean"},
		},
		Instructions: []types.Instruction{
			{Opcode: "const/4", Raw: "const/4 v0, 0x1"},
			{Opcode: "return", Raw: "return v0"},
		},
	}
	a4 := analyzer.Analyze(mGate, class)
	if !a4.FeatureMap["constant_boolean_return"] {
		t.Error("constant_boolean_return not detected")
	}
	if !a4.FeatureMap["reads_shared_preferences"] {
		t.Error("reads_shared_preferences not detected")
	}
}

func TestMethodAnalyzer_ExtractorsEdgeCases(t *testing.T) {
	// Tests names, string constants
	m := &types.SmaliMethod{
		Name: "s",
		StringConsts: []types.StringConstant{
			{Value: "premium_unlocked"},                 // premium string
			{Value: "http://example.com/check_license"}, // suspicious url
		},
	}
	m.StringConsts[1].Flags |= types.StringFlagLooksURL // simulate looks like url
	class := &types.SmaliClass{Name: "com.library"}

	ctx := &extractorContext{
		nameLower: "s",
	}

	f1 := extractShortObfuscatedName(m, class, ctx)
	if f1 == nil {
		t.Error("Should detect short name")
	}

	f2 := extractHasPremiumStrings(m, class, ctx)
	if f2 == nil {
		t.Error("Should detect premium string")
	}

	f3 := extractHasSuspiciousURLs(m, class, ctx)
	if f3 == nil {
		t.Error("Should detect suspicious url")
	}

	// Conditions
	m.Conditions = make([]types.Condition, 6)
	f4 := extractManyConditions(m, class, ctx)
	if f4 == nil {
		t.Error("Should detect many conditions")
	}

	// Result in condition
	m.ReturnsBoolean = true
	m.Conditions = []types.Condition{{Op: types.CondOpEqz}}
	f5 := extractBooleanResultInCondition(m, class, ctx)
	if f5 == nil {
		t.Error("Should detect boolean result in condition")
	}
}
