package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAndroidPatcherJSONMissingArtifactIsNotSafe(t *testing.T) {
	point := PatchPoint{FilePath: "Probe.smali", MethodName: "value", MethodSignature: "value()Z", SuggestedPatch: PatchReturnTrue, Confidence: 0.9}
	export := NewJSONExporter().buildExport(nil, []PatchPoint{point})
	if err := NewJSONExporter().validate(export); err != nil {
		t.Fatal(err)
	}
	patch := export.Patches[0]
	if patch.ApplySafe {
		t.Fatalf("missing generated patch is exported as apply_safe=true: original=%q patched=%q artifacts=%d", patch.OriginalCode, patch.PatchedCode, len(export.Artifacts))
	}
}

func androidPatcherBlockArtifact(original, patched string) *PatchArtifact {
	return &PatchArtifact{FilePath: "Probe.smali", OriginalCode: original, PatchedCode: patched,
		OriginalHash: sha256Hex(original), PatchedHash: sha256Hex(patched),
		ApplySafety: ApplySafety{Safe: true, CanWrite: true}, BlockPatch: buildBlockPatch(original, patched)}
}

func TestAndroidPatcherExactMethodWithRepeatedBlock(t *testing.T) {
	original := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\ninvoke-static {v0}, Laudit/Probe;->record(I)V\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(original, "const/4 v0, 0x0", "const/4 v0, 0x1", 1)
	artifact := androidPatcherBlockArtifact(original, patched)
	dir := t.TempDir()
	file := filepath.Join(dir, artifact.FilePath)
	if err := os.WriteFile(file, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyArtifactToBase(dir, artifact); err != nil {
		t.Fatalf("exact full-method match was rejected: %v", err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != patched {
		t.Fatalf("unexpected result: %q, %v", got, err)
	}
}

func TestAndroidPatcherBlockDoesNotConfuseUnrelatedDestination(t *testing.T) {
	original := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\ninvoke-static {v0}, Laudit/Probe;->record(I)V\nconst/4 v0, 0x1\nreturn v0\n.end method"
	patched := strings.Replace(original, "const/4 v0, 0x0", "const/4 v0, 0x1", 1)
	artifact := androidPatcherBlockArtifact(original, patched)
	drifted := strings.Replace(original, "const/4 v0, 0x0", "const/4 v0, 0x2", 1)
	dir := t.TempDir()
	file := filepath.Join(dir, artifact.FilePath)
	if err := os.WriteFile(file, []byte(drifted), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyArtifactToBase(dir, artifact); err == nil {
		t.Fatal("apply reports success although the target is still 0x2; an unrelated 0x1 is mistaken for the applied block")
	}
}

func TestAndroidPatcherAnchoredBlockDriftAndRevert(t *testing.T) {
	original := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\ninvoke-static {v0}, Laudit/Probe;->record(I)V\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(original, "const/4 v0, 0x0", "const/4 v0, 0x1", 1)
	artifact := androidPatcherBlockArtifact(original, patched)
	artifact.BlockPatch.ContextBefore, artifact.BlockPatch.ContextAfter = nil, nil // legacy metadata
	drifted := strings.Replace(original, "return v0", ".line 99\nreturn v0", 1)
	dir := t.TempDir()
	file := filepath.Join(dir, artifact.FilePath)
	if err := os.WriteFile(file, []byte(drifted), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := ApplyArtifactToBaseWithResult(dir, artifact)
	if err != nil || !changed {
		t.Fatalf("anchored repeated block: changed=%v err=%v", changed, err)
	}
	if changed, err := ApplyArtifactToBaseWithResult(dir, artifact); err != nil || changed {
		t.Fatalf("repeat: changed=%v err=%v", changed, err)
	}
	if err := RevertArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != drifted {
		t.Fatalf("independent edit lost: %q %v", got, err)
	}
}

func TestAndroidPatcherJSONRequiresValidBinding(t *testing.T) {
	original := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(original, "0x0", "0x1", 1)
	artifact := androidPatcherBlockArtifact(original, patched)
	point := PatchPoint{FilePath: artifact.FilePath, MethodName: "value", MethodSignature: "value()Z", SuggestedPatch: PatchReturnTrue}
	patch := &GeneratedPatch{FilePath: point.FilePath, MethodName: point.MethodName, MethodSignature: point.MethodSignature, PatchType: PatchReturnTrue, Artifact: artifact}
	exporter := NewJSONExporter()
	validExport := exporter.buildExport([]*GeneratedPatch{patch}, []PatchPoint{point})
	if !validExport.Patches[0].ApplySafe || !validExport.Artifacts[0].ApplySafety.Safe || !validExport.Artifacts[0].ApplySafety.CanWrite {
		t.Fatal("valid bound patch was blocked")
	}
	artifact.PatchedHash = "invalid"
	exported := exporter.buildExport([]*GeneratedPatch{patch}, []PatchPoint{point})
	got := exported.Patches[0]
	if got.ApplySafe || got.ApplySafetyLevel != "blocked" || len(got.SafetyReasons) == 0 {
		t.Fatalf("invalid binding remains writable: %+v", got)
	}
	if exported.Artifacts[0].ApplySafety.CanWrite || exported.Artifacts[0].ApplySafety.Safe || exported.Artifacts[0].ApplySafety.Level != "blocked" {
		t.Fatal("nested artifact disagrees with exported safety status")
	}
	if !artifact.ApplySafety.CanWrite {
		t.Fatal("export mutated the input artifact")
	}
}
