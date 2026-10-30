package ml

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mlHardeningOriginalMethod = ".method public static run()V\n    .locals 0\n    .line 10\n    return-void\n.end method"

func mlHardeningArtifact(original, patched string) *PatchArtifact {
	return &PatchArtifact{
		FilePath:     "Debug.smali",
		OriginalCode: original,
		PatchedCode:  patched,
		OriginalHash: sha256Hex(original),
		PatchedHash:  sha256Hex(patched),
		ApplySafety:  ApplySafety{Safe: true, CanWrite: true},
		BlockPatch:   buildBlockPatch(original, patched),
	}
}

func TestMLHardeningBlockBodyBinding(t *testing.T) {
	original := mlHardeningOriginalMethod
	patched := strings.Replace(original, ".line 10", ".line 11", 1)
	for _, reverse := range []bool{false, true} {
		for _, tamperSource := range []bool{false, true} {
			t.Run(fmt.Sprintf("reverse=%t/source=%t", reverse, tamperSource), func(t *testing.T) {
				artifact := mlHardeningArtifact(original, patched)
				if tamperSource {
					artifact.BlockPatch.OriginalLines = []string{"    .locals 0"}
					artifact.BlockPatch.OriginalHash = sha256Hex("    .locals 0")
				} else {
					artifact.BlockPatch.PatchedLines = []string{"    .line 999"}
					artifact.BlockPatch.PatchedHash = sha256Hex("    .line 999")
				}
				dir := testTempDir(t)
				file := filepath.Join(dir, artifact.FilePath)
				initial := original
				if reverse {
					initial = patched
				}
				if err := os.WriteFile(file, []byte(initial), 0600); err != nil {
					t.Fatal(err)
				}
				err := mutateArtifact(dir, artifact, reverse)
				if err == nil || !strings.Contains(err.Error(), "block does not match method bodies") {
					t.Fatalf("expected block/body rejection, got %v", err)
				}
				data, err := os.ReadFile(file)
				if err != nil || string(data) != initial {
					t.Fatalf("rejected artifact modified target: data=%q err=%v", data, err)
				}
				if _, err := os.Stat(file + ".original"); !os.IsNotExist(err) {
					t.Fatalf("rejected artifact created a backup: %v", err)
				}
			})
		}
	}
}

func TestMLHardeningEmptySidedEditsRoundTrip(t *testing.T) {
	withLine := mlHardeningOriginalMethod
	withoutLine := strings.Replace(withLine, "    .line 10\n", "", 1)
	for _, insertion := range []bool{false, true} {
		for _, crlf := range []bool{false, true} {
			for _, trailing := range []bool{false, true} {
				t.Run(fmt.Sprintf("insert=%t/CRLF=%t/trailing=%t", insertion, crlf, trailing), func(t *testing.T) {
					original, patched := withLine, withoutLine
					if insertion {
						original, patched = patched, original
					}
					artifact := mlHardeningArtifact(original, patched)
					dir := testTempDir(t)
					file := filepath.Join(dir, artifact.FilePath)
					ending := "\n"
					if crlf {
						ending = "\r\n"
					}
					style := func(method string) string {
						text := strings.ReplaceAll(".class public LDebug;\n.super Ljava/lang/Object;\n"+method, "\n", ending)
						if trailing {
							text += ending
						}
						return text
					}
					initial := style(original)
					if err := os.WriteFile(file, []byte(initial), 0600); err != nil {
						t.Fatal(err)
					}
					for _, reverse := range []bool{false, false, true, true} {
						if err := mutateArtifact(dir, artifact, reverse); err != nil {
							t.Fatalf("reverse=%v: %v", reverse, err)
						}
						want := style(patched)
						if reverse {
							want = initial
						}
						data, err := os.ReadFile(file)
						if err != nil || string(data) != want {
							t.Fatalf("round trip mismatch: data=%q want=%q err=%v", data, want, err)
						}
					}
					backup, err := os.ReadFile(file + ".original")
					if err != nil || string(backup) != initial {
						t.Fatalf("backup changed: data=%q err=%v", backup, err)
					}
				})
			}
		}
	}
}

func TestMLHardeningBlockPreservesUnrelatedEdit(t *testing.T) {
	original := mlHardeningOriginalMethod
	patched := strings.Replace(original, ".line 10", ".line 11", 1)
	artifact := mlHardeningArtifact(original, patched)
	dir := testTempDir(t)
	file := filepath.Join(dir, artifact.FilePath)
	independent := "    # independent diagnostic comment\n"
	initial := strings.Replace(original, "    return-void", independent+"    return-void", 1)
	if err := os.WriteFile(file, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	if err := RevertArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != initial {
		t.Fatalf("unrelated edit was lost: data=%q err=%v", data, err)
	}
}

func TestMLHardeningAtomicRenameFailure(t *testing.T) {
	dir := testTempDir(t)
	file := filepath.Join(dir, "Debug.smali")
	initial := []byte("original bytes must survive")
	if err := os.WriteFile(file, initial, 0600); err != nil {
		t.Fatal(err)
	}
	renameFailure := errors.New("simulated sharing violation")
	called := false
	err := writeFileAtomicWithRename(file, []byte("replacement"), 0600, func(source, destination string) error {
		called = true
		if filepath.Dir(source) != dir || destination != file {
			t.Fatalf("unexpected rename: %q -> %q", source, destination)
		}
		return renameFailure
	})
	if !called || !errors.Is(err, renameFailure) {
		t.Fatalf("rename error was swallowed: called=%v err=%v", called, err)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != string(initial) {
		t.Fatalf("failed replacement modified destination: data=%q err=%v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "Debug.smali" {
		t.Fatalf("temporary file leaked: entries=%v err=%v", entries, err)
	}
}

func TestMLHardeningResolveMissingTargetFailsClosed(t *testing.T) {
	if _, err := resolveArtifactTarget(testTempDir(t), "missing.smali"); err == nil {
		t.Fatal("unresolved target was accepted")
	}
}

func TestMLHardeningRejectsNonRegularFiles(t *testing.T) {
	original := mlHardeningOriginalMethod
	patched := strings.Replace(original, ".line 10", ".line 11", 1)
	for _, kind := range []string{"target-directory", "backup-directory", "backup-symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := testTempDir(t)
			artifact := mlHardeningArtifact(original, patched)
			file := filepath.Join(dir, artifact.FilePath)
			if kind == "target-directory" {
				if err := os.Mkdir(file, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(file, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "backup-directory" {
					if err := os.Mkdir(file+".original", 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Symlink(file, file+".original"); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				}
			}
			if err := ApplyArtifactToBase(dir, artifact); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("expected regular-file guard, got %v", err)
			}
			if kind != "target-directory" {
				data, err := os.ReadFile(file)
				if err != nil || string(data) != original {
					t.Fatalf("rejected target was modified: data=%q err=%v", data, err)
				}
			}
		})
	}
}

func TestMLHardeningRejectsNestedMethodBounds(t *testing.T) {
	lines := []string{
		".method public static run()V",
		"    .locals 0",
		"    return-void",
		".method public static other()V",
		"    .locals 0",
		"    return-void",
		".end method",
	}
	if _, _, err := uniqueMethodBounds(lines, lines[0]); err == nil {
		t.Fatal("method bounds crossed into a neighbouring method")
	}
}
