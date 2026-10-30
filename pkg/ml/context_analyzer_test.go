package ml

import (
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// TestNewContextAnalyzer verifies that NewContextAnalyzer creates a properly initialized instance
func TestNewContextAnalyzer(t *testing.T) {
	ca := NewContextAnalyzer()

	if ca == nil {
		t.Fatal("NewContextAnalyzer returned nil")
	}

	if ca.classPatterns == nil {
		t.Error("classPatterns map is nil")
	}

	if ca.packageRules == nil {
		t.Error("packageRules slice is nil")
	}

	// Verify some default patterns are loaded
	if len(ca.classPatterns) == 0 {
		t.Error("classPatterns is empty, expected default patterns")
	}

	if len(ca.packageRules) == 0 {
		t.Error("packageRules is empty, expected default rules")
	}
}

// TestDetermineCheckType_ClassPatterns tests class name pattern matching
func TestDetermineCheckType_ClassPatterns(t *testing.T) {
	ca := NewContextAnalyzer()

	tests := []struct {
		name      string
		className string
		expected  shared.SecurityCheckType
	}{
		{"Root detection class", "RootDetector", shared.CheckTypeRoot},
		{"Root check class", "RootCheckUtil", shared.CheckTypeRoot},
		{"Premium class", "PremiumManager", shared.CheckTypePremium},
		{"License class", "LicenseValidator", shared.CheckTypePremium},
		{"Emulator class", "EmulatorDetector", shared.CheckTypeEmulator},
		{"Billing class", "BillingHelper", shared.CheckTypeBilling},
		{"Purchase class", "PurchaseManager", shared.CheckTypeBilling},
		{"Tamper class", "TamperDetection", shared.CheckTypeTamper},
		{"Debug class", "DebugDetector", shared.CheckTypeDebug},
		{"Unknown class", "MainActivity", shared.CheckTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &shared.MethodInfo{
				ClassName: tt.className,
				Name:      "checkSomething",
				FilePath:  "com/example/app/MainActivity.smali",
			}

			result := ca.DetermineCheckType(mi)
			if result != tt.expected {
				t.Errorf("DetermineCheckType(%s) = %v, want %v", tt.className, result, tt.expected)
			}
		})
	}
}

// TestDetermineCheckType_PackageRules tests package path pattern matching
func TestDetermineCheckType_PackageRules(t *testing.T) {
	ca := NewContextAnalyzer()

	tests := []struct {
		name     string
		filePath string
		expected shared.SecurityCheckType
	}{
		{"Root package", "com/example/root/RootUtil.smali", shared.CheckTypeRoot},
		{"Premium package", "com/example/premium/Manager.smali", shared.CheckTypePremium},
		{"License package", "com/example/license/Checker.smali", shared.CheckTypePremium},
		{"Emulator package", "com/example/emulator/Detector.smali", shared.CheckTypeEmulator},
		{"Billing package", "com/example/billing/Helper.smali", shared.CheckTypeBilling},
		{"Purchase package", "com/example/purchase/Manager.smali", shared.CheckTypeBilling},
		{"Tamper package", "com/example/tamper/Detection.smali", shared.CheckTypeTamper},
		{"Debug package", "com/example/debug/Detector.smali", shared.CheckTypeDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &shared.MethodInfo{
				ClassName: "SomeClass",
				Name:      "checkSomething",
				FilePath:  tt.filePath,
			}

			result := ca.DetermineCheckType(mi)
			if result != tt.expected {
				t.Errorf("DetermineCheckType(%s) = %v, want %v", tt.filePath, result, tt.expected)
			}
		})
	}
}

// TestInferFromMethodName tests method name inference
func TestInferFromMethodName(t *testing.T) {
	ca := NewContextAnalyzer()

	tests := []struct {
		name       string
		methodName string
		expected   shared.SecurityCheckType
	}{
		{"Root method", "isRooted", shared.CheckTypeRoot},
		{"SU method", "checkSuBinary", shared.CheckTypeRoot},
		{"Premium method", "isPremiumUser", shared.CheckTypePremium},
		{"License method", "validateLicense", shared.CheckTypePremium},
		{"Subscription method", "hasActiveSubscription", shared.CheckTypePremium},
		{"Emulator method", "isEmulator", shared.CheckTypeEmulator},
		{"Virtual method", "detectVirtualEnvironment", shared.CheckTypeEmulator},
		{"Billing method", "processBilling", shared.CheckTypeBilling},
		{"Purchase method", "handlePurchase", shared.CheckTypeBilling},
		{"Tamper method", "checkTamper", shared.CheckTypeTamper},
		{"Integrity method", "verifyIntegrity", shared.CheckTypeTamper},
		{"Debug method", "isDebuggerAttached", shared.CheckTypeDebug},
		{"Unknown method", "doSomething", shared.CheckTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &shared.MethodInfo{
				ClassName: "SomeClass",
				Name:      tt.methodName,
				FilePath:  "com/example/app/SomeClass.smali",
			}

			result := ca.inferFromMethodName(mi)
			if result != tt.expected {
				t.Errorf("inferFromMethodName(%s) = %v, want %v", tt.methodName, result, tt.expected)
			}
		})
	}
}

// TestGetDesiredReturn_DefensiveMode tests patch type selection in defensive mode
func TestGetDesiredReturn_DefensiveMode(t *testing.T) {
	ca := NewContextAnalyzer()
	mode := PatchModeDefensive

	tests := []struct {
		name      string
		checkType shared.SecurityCheckType
		expected  shared.PatchType
	}{
		{"Root detection", shared.CheckTypeRoot, shared.PatchReturnTrue},
		{"Emulator detection", shared.CheckTypeEmulator, shared.PatchReturnTrue},
		{"Debug detection", shared.CheckTypeDebug, shared.PatchReturnTrue},
		{"Tamper detection", shared.CheckTypeTamper, shared.PatchReturnTrue},
		{"Premium check", shared.CheckTypePremium, shared.PatchReturnFalse},
		{"Billing check", shared.CheckTypeBilling, shared.PatchReturnFalse},
		{"Unknown check", shared.CheckTypeUnknown, shared.PatchReturnTrue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ca.GetDesiredReturn(tt.checkType, mode)
			if result != tt.expected {
				t.Errorf("GetDesiredReturn(%v, defensive) = %v, want %v", tt.checkType, result, tt.expected)
			}
		})
	}
}

// TestGetDesiredReturn_ResearchMode tests patch type selection in research mode
func TestGetDesiredReturn_ResearchMode(t *testing.T) {
	ca := NewContextAnalyzer()
	mode := PatchModeResearch

	tests := []struct {
		name      string
		checkType shared.SecurityCheckType
		expected  shared.PatchType
	}{
		{"Root detection", shared.CheckTypeRoot, shared.PatchReturnFalse},
		{"Emulator detection", shared.CheckTypeEmulator, shared.PatchReturnFalse},
		{"Debug detection", shared.CheckTypeDebug, shared.PatchReturnFalse},
		{"Tamper detection", shared.CheckTypeTamper, shared.PatchReturnFalse},
		{"Premium check", shared.CheckTypePremium, shared.PatchReturnTrue},
		{"Billing check", shared.CheckTypeBilling, shared.PatchReturnTrue},
		{"Unknown check", shared.CheckTypeUnknown, shared.PatchReturnTrue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ca.GetDesiredReturn(tt.checkType, mode)
			if result != tt.expected {
				t.Errorf("GetDesiredReturn(%v, research) = %v, want %v", tt.checkType, result, tt.expected)
			}
		})
	}
}

// TestDetermineCheckType_Priority tests that class patterns take priority over package rules
func TestDetermineCheckType_Priority(t *testing.T) {
	ca := NewContextAnalyzer()

	// Class name should take priority over package path
	mi := &shared.MethodInfo{
		ClassName: "RootDetector", // Root in class name
		Name:      "checkSomething",
		FilePath:  "com/example/premium/RootDetector.smali", // Premium in path
	}

	result := ca.DetermineCheckType(mi)
	if result != shared.CheckTypeRoot {
		t.Errorf("Expected class pattern to take priority, got %v", result)
	}
}

// TestDetermineCheckType_MethodNameFallback tests fallback to method name analysis
func TestDetermineCheckType_MethodNameFallback(t *testing.T) {
	ca := NewContextAnalyzer()

	// No class or package match, should use method name
	mi := &shared.MethodInfo{
		ClassName: "MainActivity",
		Name:      "isRooted",
		FilePath:  "com/example/app/MainActivity.smali",
	}

	result := ca.DetermineCheckType(mi)
	if result != shared.CheckTypeRoot {
		t.Errorf("Expected method name fallback to detect root, got %v", result)
	}
}
