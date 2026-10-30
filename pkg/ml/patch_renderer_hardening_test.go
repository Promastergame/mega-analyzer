package ml

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mlHardeningLongMethod(size int) string {
	lines := []string{".method public static run()V", "    .locals 0"}
	for i := 0; i < size; i++ {
		lines = append(lines, fmt.Sprintf("    nop # instruction %d", i))
	}
	lines = append(lines, "    return-void", ".end method")
	return strings.Join(lines, "\n")
}

func TestMLHardeningUnifiedDiffIsLossless(t *testing.T) {
	for _, size := range []int{15, 16, 17, 64, 256} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			original := mlHardeningLongMethod(size)
			patched := strings.Replace(original, "    nop # instruction 10", "    nop # updated diagnostic", 1)
			diff := buildUnifiedDiff("Debug.smali", original, patched)
			if got := extractOriginalFromUnifiedDiff(diff); got != original {
				t.Fatalf("original method lost in machine-readable diff:\n%s", diff)
			}
			if got := extractPatchedFromUnifiedDiff(diff); got != patched {
				t.Fatalf("patched method lost in machine-readable diff:\n%s", diff)
			}
			oldCount, newCount := 0, 0
			inHunk := false
			for _, line := range strings.Split(diff, "\n") {
				if strings.HasPrefix(line, "@@ ") {
					inHunk = true
					continue
				}
				if !inHunk || line == "" {
					continue
				}
				switch line[0] {
				case '-':
					oldCount++
				case '+':
					newCount++
				}
			}
			if oldCount != size+4 || newCount != size+4 {
				t.Fatalf("hunk content counts = %d/%d, want %d/%d", oldCount, newCount, size+4, size+4)
			}
			wantHeader := fmt.Sprintf("@@ -1,%d +1,%d @@", oldCount, newCount)
			if !strings.Contains(diff, wantHeader) {
				t.Fatalf("hunk counts do not agree with %q", wantHeader)
			}
		})
	}
}

func TestMLHardeningLegacyLargeDiffRoundTrip(t *testing.T) {
	original := mlHardeningLongMethod(64)
	patched := strings.Replace(original, "    nop # instruction 30", "    nop # updated diagnostic", 1)
	artifact := mlHardeningArtifact(original, patched)
	artifact.UnifiedDiff = buildUnifiedDiff(artifact.FilePath, original, patched)
	artifact.OriginalCode, artifact.PatchedCode = "", ""
	artifact.BlockPatch = nil // legacy artifact carries only the full unified diff
	dir := testTempDir(t)
	file := filepath.Join(dir, artifact.FilePath)
	initial := ".class public LDebug;\n.super Ljava/lang/Object;\n" + original + "\n"
	if err := os.WriteFile(file, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), patched) {
		t.Fatalf("legacy apply failed: data=%q err=%v", data, err)
	}
	if err := RevertArtifactToBase(dir, artifact); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(file)
	if err != nil || string(data) != initial {
		t.Fatalf("legacy revert failed: data=%q err=%v", data, err)
	}
}
