package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchLookupKeyDistinguishesOverloads(t *testing.T) {
	a := patchLookupKey("smali/A.smali", "check", "(I)Z")
	b := patchLookupKey("smali/A.smali", "check", "(Ljava/lang/String;)Z")
	if a == b {
		t.Fatalf("overloaded methods collided: %q", a)
	}
}

func TestApplyArtifactRejectsPathTraversal(t *testing.T) {
	artifact := &PatchArtifact{FilePath: "../escape.smali", ApplySafety: ApplySafety{CanWrite: true}}
	if err := ApplyArtifactToBase(testTempDir(t), artifact); err == nil || !strings.Contains(err.Error(), "escapes base") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestApplyAndRevertArtifactAreIndependentAndIdempotent(t *testing.T) {
	dir := testTempDir(t)
	path := filepath.Join(dir, "Gate.smali")
	method := ".method public check()Z\n    .registers 1\n    const/4 v0, 0x0\n    return v0\n.end method"
	patched := strings.Replace(method, "const/4 v0, 0x0", "const/4 v0, 0x1", 1)
	file := ".class public LGate;\n" + method + "\n"
	if err := os.WriteFile(path, []byte(file), 0640); err != nil {
		t.Fatal(err)
	}
	artifact := &PatchArtifact{
		FilePath: "Gate.smali", MethodName: "check", MethodSignature: "()Z",
		OriginalCode: method, PatchedCode: patched,
		OriginalHash: sha256Hex(method), PatchedHash: sha256Hex(patched),
		ApplySafety: ApplySafety{Safe: true, Level: "safe", CanWrite: true},
		BlockPatch:  buildBlockPatch(method, patched),
	}
	if err := ApplyArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	if err := ApplyArtifactToBase(dir, artifact); err != nil {
		t.Fatalf("second apply must be idempotent: %v", err)
	}
	if err := RevertArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	if err := RevertArtifactToBase(dir, artifact); err != nil {
		t.Fatalf("second revert must be idempotent: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != file {
		t.Fatalf("revert mismatch:\n%s", got)
	}
}

func TestJSONExporterKeepsOverloadedMethodsDistinct(t *testing.T) {
	patches := []*GeneratedPatch{
		{FilePath: "A.smali", MethodName: "check", MethodSignature: "(I)Z", PatchType: PatchReturnTrue, OriginalCode: "int-original", PatchedCode: "int-patched", Confidence: 0.9},
		{FilePath: "A.smali", MethodName: "check", MethodSignature: "(Ljava/lang/String;)Z", PatchType: PatchReturnFalse, OriginalCode: "string-original", PatchedCode: "string-patched", Confidence: 0.8},
	}
	points := []PatchPoint{
		{FilePath: "A.smali", MethodName: "check", MethodSignature: "(I)Z", SuggestedPatch: PatchReturnTrue, RiskScore: 80, Confidence: 0.9},
		{FilePath: "A.smali", MethodName: "check", MethodSignature: "(Ljava/lang/String;)Z", SuggestedPatch: PatchReturnFalse, RiskScore: 70, Confidence: 0.8},
	}
	export := NewJSONExporter().buildExport(patches, points)
	if len(export.Patches) != 2 {
		t.Fatalf("got %d patches", len(export.Patches))
	}
	if export.Patches[0].PatchedCode != "int-patched" || export.Patches[1].PatchedCode != "string-patched" {
		t.Fatalf("overloads mapped to wrong generated patches: %#v", export.Patches)
	}
	if export.Patches[0].PatchID == export.Patches[1].PatchID {
		t.Fatal("overloads received identical patch IDs")
	}
}

func TestApplyArtifactRejectsSymlinkEscape(t *testing.T) {
	base := testTempDir(t)
	outside := filepath.Join(testTempDir(t), "outside.smali")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.smali")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	artifact := &PatchArtifact{FilePath: "link.smali", ApplySafety: ApplySafety{CanWrite: true}}
	if err := ApplyArtifactToBase(base, artifact); err == nil || !strings.Contains(err.Error(), "symlink target escapes") {
		t.Fatalf("expected symlink containment error, got %v", err)
	}
}
