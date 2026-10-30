package ml

import (
	"strings"
	"testing"
)

func TestSmartPatchUsesTypedBuilderForWideParameters(t *testing.T) {
	patch := &SmartPatch{
		MethodSig:  "Lcom/example/Check;->isValid(JJ)Z",
		Confidence: 0.95,
		Strategy:   SmartPatchStrategy{Type: "return_true"},
	}
	patch.BindSource([]string{".method public isValid(JJ)Z", "    .locals 0", "    const/4 v0, 0x0", "    return v0", ".end method"})
	artifact := patch.ToPatchArtifact()
	if artifact == nil {
		t.Fatal("artifact is nil")
	}
	if !artifact.Validation.Valid || !artifact.ApplySafety.CanWrite {
		t.Fatalf("wide-parameter patch was blocked: validation=%+v safety=%+v", artifact.Validation, artifact.ApplySafety)
	}
	if !strings.Contains(artifact.PatchedCode, ".registers 6") || !strings.Contains(artifact.PatchedCode, "const/4 v0, 0x1") {
		t.Fatalf("unexpected generated code:\n%s", artifact.PatchedCode)
	}
}

func TestSmartPatchRejectsReturnTrueForNonBoolean(t *testing.T) {
	artifact := (&SmartPatch{
		MethodSig:  "Lcom/example/Value;->value(J)J",
		Confidence: 0.99,
		Strategy:   SmartPatchStrategy{Type: "return_true"},
	}).ToPatchArtifact()
	if artifact == nil || artifact.ApplySafety.CanWrite || artifact.Validation.Valid {
		t.Fatalf("incompatible SmartPatch should be blocked: %+v", artifact)
	}
}

func TestSmartPatchRejectsPlaceholderConstReplacement(t *testing.T) {
	artifact := (&SmartPatch{
		MethodSig:  "Lcom/example/Api;->url()Ljava/lang/String;",
		Confidence: 0.99,
		Strategy:   SmartPatchStrategy{Type: "const_replace", NewConst: "https://example.invalid"},
	}).ToPatchArtifact()
	if artifact == nil || artifact.ApplySafety.CanWrite || artifact.PatchedCode != "" {
		t.Fatalf("placeholder const replacement must not be writable: %+v", artifact)
	}
}
