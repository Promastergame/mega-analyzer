package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyArtifactToBase_BlockPatchOnlyChangedLine(t *testing.T) {
	dir := testTempDir(t)
	file := filepath.Join(dir, "Gate.smali")
	original := strings.Join([]string{
		".class public LGate;",
		".super Ljava/lang/Object;",
		".method public check()Z",
		"    .registers 1",
		"    invoke-static {}, Lsec/License;->isLicensed()Z",
		"    move-result v0",
		"    if-eqz v0, :fail",
		"    const/4 v0, 0x1",
		"    return v0",
		":fail",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}, "\n")
	if err := os.WriteFile(file, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	methodOriginal := strings.Join(strings.Split(original, "\n")[2:], "\n")
	methodPatched := strings.Replace(methodOriginal, "    if-eqz v0, :fail", "    if-nez v0, :fail", 1)
	artifact := &PatchArtifact{
		FilePath:     "Gate.smali",
		OriginalCode: methodOriginal,
		PatchedCode:  methodPatched,
		OriginalHash: sha256Hex(methodOriginal),
		PatchedHash:  sha256Hex(methodPatched),
		ApplySafety:  ApplySafety{Safe: true, Level: "safe", CanWrite: true},
		BlockPatch:   buildBlockPatch(methodOriginal, methodPatched),
	}
	if artifact.BlockPatch == nil || len(artifact.BlockPatch.OriginalLines) != 1 {
		t.Fatalf("expected one-line block patch, got %#v", artifact.BlockPatch)
	}

	if err := ApplyArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	updated := string(data)
	if !strings.Contains(updated, "    if-nez v0, :fail") {
		t.Fatalf("patched line missing:\n%s", updated)
	}
	if !strings.Contains(updated, "    invoke-static {}, Lsec/License;->isLicensed()Z") {
		t.Fatalf("surrounding block was not preserved:\n%s", updated)
	}
}
