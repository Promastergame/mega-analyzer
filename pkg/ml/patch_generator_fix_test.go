package ml

import (
	"testing"
)

// TestGenerateWithMode_StrategyFound tests the case when a strategy is found
func TestGenerateWithMode_StrategyFound(t *testing.T) {
	pg := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:      "isRooted",
		ClassName:       "com/example/Security",
		FilePath:        "com/example/Security.smali",
		MethodSignature: "()Z",
		ReturnType:      "Z",
		SuggestedPatch:  PatchReturnFalse,
		MethodHeader:    ".method public isRooted()Z",
		MethodBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    const/4 v0, 0x1",
			"    return v0",
			".end method",
		},
		IsAppCode: true,
	}

	// Call GenerateWithMode directly
	patch := pg.GenerateWithMode(point, PatchModeDefensive)

	if patch == nil {
		t.Fatal("Expected patch to be generated, got nil")
	}

	if patch.MethodName != "isRooted" {
		t.Errorf("Expected method name 'isRooted', got '%s'", patch.MethodName)
	}
}

// TestGenerate_NoModeSet tests the legacy behavior when no mode is set
func TestGenerate_NoModeSet(t *testing.T) {
	pg := NewPatchGenerator()
	// Don't set mode

	point := &PatchPoint{
		MethodName:      "isPremium",
		ClassName:       "com/example/License",
		FilePath:        "com/example/License.smali",
		MethodSignature: "()Z",
		ReturnType:      "Z",
		SuggestedPatch:  PatchReturnTrue,
		MethodHeader:    ".method public isPremium()Z",
		MethodBody: []string{
			".method public isPremium()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
		IsAppCode: true,
	}

	// This should use legacy behavior
	patch := pg.Generate(point)

	if patch == nil {
		t.Fatal("Expected patch to be generated, got nil")
	}

	if patch.MethodName != "isPremium" {
		t.Errorf("Expected method name 'isPremium', got '%s'", patch.MethodName)
	}
}
