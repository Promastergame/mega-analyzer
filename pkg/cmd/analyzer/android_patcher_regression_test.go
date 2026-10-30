package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/ml"
)

func TestAndroidPatcherConfidenceFilterPreservesOverload(t *testing.T) {
	patches := []*ml.GeneratedPatch{
		{FilePath: "Probe.smali", MethodName: "value", MethodSignature: "value(I)Z", Confidence: 0.95},
		{FilePath: "Probe.smali", MethodName: "value", MethodSignature: "value(Ljava/lang/String;)Z", Confidence: 0.2},
	}
	points := []ml.PatchPoint{
		{FilePath: "Probe.smali", MethodName: "value", MethodSignature: "value(I)Z", Confidence: 0.95},
		{FilePath: "Probe.smali", MethodName: "value", MethodSignature: "value(Ljava/lang/String;)Z", Confidence: 0.2},
	}
	got, kept := NewApp().filterPatchesByConfidence(patches, points, 0.8)
	if len(got) != 1 || len(kept) != 1 {
		t.Fatalf("unexpected counts %d %d", len(got), len(kept))
	}
	if got[0].MethodSignature != kept[0].MethodSignature {
		t.Fatalf("point %s (%.2f) paired with patch %s (%.2f)", kept[0].MethodSignature, kept[0].Confidence, got[0].MethodSignature, got[0].Confidence)
	}
}

func TestAndroidPatcherDEXFailedBatchReturnsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "classes.dex"), []byte("invalid dex"), 0600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	app := &App{output: NewOutputWithWriter(NoColorTheme(), false, &log)}
	artifact := &ml.PatchArtifact{FilePath: "audit/Probe.smali", MethodSignature: "Laudit/Probe;->value()Z", PatchType: ml.PatchReturnTrue, ApplySafety: ml.ApplySafety{CanWrite: true}}
	if err := app.applyPatchesDEX([]*ml.PatchArtifact{artifact}, dir); err == nil {
		t.Fatalf("all patches failed but batch returned nil; log: %s", log.String())
	}
}

func androidPatcherWriteDEX(t *testing.T, dir, method string) string {
	t.Helper()
	src := ".class public Laudit/Probe;\n.super Ljava/lang/Object;\n" + method + "\n.method public static record()V\n.locals 0\nreturn-void\n.end method\n"
	data, _, err := apkloader.AssembleSmaliText("Probe.smali", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "classes.dex")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func androidPatcherArtifact(original, patched string) *ml.PatchArtifact {
	return &ml.PatchArtifact{FilePath: "audit/Probe.smali", MethodSignature: "Laudit/Probe;->value()Z", MethodName: "value", PatchType: ml.PatchReturnTrue,
		OriginalCode: original, PatchedCode: patched, OriginalHash: fmt.Sprintf("%x", sha256.Sum256([]byte(original))), PatchedHash: fmt.Sprintf("%x", sha256.Sum256([]byte(patched))),
		ApplySafety: ml.ApplySafety{Safe: true, CanWrite: true}}
}

func TestAndroidPatcherDEXPreservesReviewedCode(t *testing.T) {
	original := ".method public static value()Z\n.locals 1\ninvoke-static {}, Laudit/Probe;->record()V\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(original, "const/4 v0, 0x0", "const/4 v0, 0x1", 1)
	file := androidPatcherWriteDEX(t, t.TempDir(), original)
	if err := NewApp().applyPatchToDEX(androidPatcherArtifact(original, patched), file); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	p, err := apkloader.ParseDEXBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	cls := p.FindClassByName("Laudit/Probe;")
	for _, m := range cls.DirectMethods {
		if m.Name == "value" {
			if len(m.Code.Insns) == 0 || byte(m.Code.Insns[0]) != 0x71 {
				t.Fatalf("DEX output discarded invoke-static preserved in the reviewed PatchedCode; words=%04x", m.Code.Insns)
			}
			return
		}
	}
	t.Fatal("patched method missing")
}

func TestAndroidPatcherDEXRejectsSourceDrift(t *testing.T) {
	original := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(original, "0x0", "0x1", 1)
	drifted := strings.Replace(original, "0x0", "0x2", 1)
	file := androidPatcherWriteDEX(t, t.TempDir(), drifted)
	if err := NewApp().applyPatchToDEX(androidPatcherArtifact(original, patched), file); err == nil {
		t.Fatal("DEX method changed since artifact creation, but apply ignored OriginalCode/OriginalHash and reported success")
	}
}

func TestAndroidPatcherMaterializedDEXApplyAndReport(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt=%v", corrupt), func(t *testing.T) {
			input, output := t.TempDir(), t.TempDir()
			method := ".method public isRooted()Z\n.registers 2\nconst/4 v0, 0x1\nreturn v0\n.end method"
			dexFile := androidPatcherWriteDEX(t, input, method)
			before, err := os.ReadFile(dexFile)
			if err != nil {
				t.Fatal(err)
			}
			app := &App{opts: &CLIOptions{MLPatchMode: "research", MLPatchBackend: "dex", MLPatchApply: "write"}, output: NewOutputWithWriter(NoColorTheme(), false, io.Discard)}
			sources, err := app.preparePatchSources(t.Context(), input, output)
			if err != nil {
				t.Fatal(err)
			}
			if sources.SmaliDir == input || len(apkloader.FindDEXFiles(sources.SmaliDir)) != 0 {
				t.Fatal("fixture must use a separate Smali tree without DEX files")
			}
			smali, err := os.ReadFile(filepath.Join(sources.SmaliDir, "audit", "Probe.smali"))
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(string(smali), ".method public isRooted()Z")
			if start < 0 {
				t.Fatal("materialized method missing")
			}
			rest := string(smali)[start:]
			end := strings.Index(rest, ".end method")
			if end < 0 {
				t.Fatal("method end missing")
			}
			body := strings.Split(rest[:end+len(".end method")], "\n")
			point := ml.PatchPoint{FilePath: "audit/Probe.smali", ClassName: "audit/Probe", MethodName: "isRooted", MethodSignature: "()Z", MethodHeader: body[0], MethodBody: body, ReturnType: "Z", SuggestedPatch: ml.PatchReturnFalse, IsAppCode: true, Confidence: 0.95}
			prediction := &ml.PatchPrediction{HighRisk: []ml.PatchPoint{point}}
			if corrupt {
				if err := os.WriteFile(dexFile, []byte("corrupt DEX"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			files, applyErr := app.handlePatchArtifacts(prediction, sources, output)
			if len(files) != 2 {
				t.Fatalf("plan and result must be saved even on failure: files=%v err=%v", files, applyErr)
			}
			readReport := func() patchApplySummary {
				data, err := os.ReadFile(filepath.Join(output, "patch_artifacts", "patch_apply_results.json"))
				if err != nil {
					t.Fatal(err)
				}
				var report patchApplySummary
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				return report
			}
			report := readReport()
			if corrupt {
				if applyErr == nil || report.Failed != 1 || report.Applied != 0 || report.Results[0].Reason == "" {
					t.Fatalf("lost application failure: report=%+v err=%v", report, applyErr)
				}
				return
			}
			if applyErr != nil || report.Applied != 1 || report.Failed != 0 {
				t.Fatalf("materialized DEX apply: report=%+v err=%v", report, applyErr)
			}
			after, err := os.ReadFile(dexFile)
			if err != nil || bytes.Equal(before, after) {
				t.Fatalf("original DEX was not patched: %v", err)
			}
			if _, err := app.handlePatchArtifacts(prediction, sources, output); err != nil {
				t.Fatal(err)
			}
			report = readReport()
			if report.AlreadyApplied != 1 || report.Applied != 0 {
				t.Fatalf("repeat reported as a new write: %+v", report)
			}
			backup, err := os.ReadFile(dexFile + ".backup")
			if err != nil || !bytes.Equal(backup, before) {
				t.Fatalf("first backup lost: %v", err)
			}
		})
	}
}

func TestAndroidPatcherBatchPartialFailureAndBackup(t *testing.T) {
	method := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\nreturn v0\n.end method"
	patched := strings.Replace(method, "0x0", "0x1", 1)
	dir := t.TempDir()
	file := androidPatcherWriteDEX(t, dir, method)
	originalDEX, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	valid := androidPatcherArtifact(method, patched)
	invalid := androidPatcherArtifact(method, patched)
	invalid.OriginalHash = "invalid"
	blocked := androidPatcherArtifact(method, patched)
	blocked.ApplySafety.CanWrite = false
	app := &App{output: NewOutputWithWriter(NoColorTheme(), true, io.Discard)}
	report, err := app.applyPatchBatch([]*ml.PatchArtifact{valid, invalid, nil, blocked}, patchSources{DEXDir: dir}, "dex")
	if err == nil || report.Applied != 1 || report.Failed != 2 || report.Skipped != 1 || len(report.Results) != 4 {
		t.Fatalf("incorrect partial result: %+v, %v", report, err)
	}
	reverse := androidPatcherArtifact(patched, method)
	reverse.PatchType = ml.PatchReturnFalse
	if err := app.applyPatchToDEX(reverse, file); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(file + ".backup")
	if err != nil || !bytes.Equal(backup, originalDEX) {
		t.Fatalf("second write replaced the original backup: %v", err)
	}
}

func TestAndroidPatcherDEXHashFailureDoesNotWrite(t *testing.T) {
	method := ".method public static value()Z\n.locals 1\nconst/4 v0, 0x0\nreturn v0\n.end method"
	file := androidPatcherWriteDEX(t, t.TempDir(), method)
	before, _ := os.ReadFile(file)
	artifact := androidPatcherArtifact(method, strings.Replace(method, "0x0", "0x1", 1))
	artifact.PatchedHash = "invalid"
	if err := NewApp().applyPatchToDEX(artifact, file); err == nil {
		t.Fatal("tampered destination hash accepted")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected patch changed the DEX")
	}
	if _, err := os.Stat(file + ".backup"); !os.IsNotExist(err) {
		t.Fatalf("rejected patch created a backup: %v", err)
	}
}

func TestAndroidPatcherMultidexDescriptor(t *testing.T) {
	artifact := androidPatcherArtifact("", "")
	artifact.FilePath = "smali_classes12/audit/Probe.smali"
	artifact.MethodSignature = "()Z"
	got, err := artifactMethodDescriptor(artifact)
	if err != nil || got != "Laudit/Probe;->value()Z" {
		t.Fatalf("descriptor=%q err=%v", got, err)
	}
}
