package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type PatchArtifact struct {
	PatchID         string              `json:"patch_id"`
	SchemaVersion   string              `json:"schema_version"`
	MethodName      string              `json:"method_name"`
	FilePath        string              `json:"file_path"`
	MethodSignature string              `json:"method_signature"`
	PatchType       PatchType           `json:"patch_type"`
	OriginalCode    string              `json:"original_code"`
	PatchedCode     string              `json:"patched_code"`
	OriginalHash    string              `json:"original_hash"`
	PatchedHash     string              `json:"patched_hash"`
	UnifiedDiff     string              `json:"unified_diff"`
	Validation      ValidationResult    `json:"validation"`
	ApplySafety     ApplySafety         `json:"apply_safety"`
	BlockPatch      *BlockPatch         `json:"block_patch,omitempty"`
	ReturnCoverage  *ReturnSiteCoverage `json:"return_coverage,omitempty"`
}

// BlockPatch is a minimal changed basic-block/window patch. It lets the applier
// modify only the affected block instead of replacing the whole method body.
type BlockPatch struct {
	StartLine     int      `json:"start_line"`
	EndLine       int      `json:"end_line"`
	OriginalLines []string `json:"original_lines"`
	PatchedLines  []string `json:"patched_lines"`
	OriginalHash  string   `json:"original_hash"`
	PatchedHash   string   `json:"patched_hash"`
	ContextBefore []string `json:"context_before,omitempty"`
	ContextAfter  []string `json:"context_after,omitempty"`
}

type ApplySafety struct {
	Safe     bool     `json:"safe"`
	Level    string   `json:"level"`
	Reasons  []string `json:"reasons,omitempty"`
	CanWrite bool     `json:"can_write"`
}

// ValidatedBodies returns the canonical, source-bound bodies used by binary
// backends and exporters. A writable flag alone does not bind an artifact to
// the code that was actually validated.
func (a *PatchArtifact) ValidatedBodies() (string, string, error) {
	if a == nil {
		return "", "", fmt.Errorf("patch artifact is missing")
	}
	if !a.ApplySafety.CanWrite {
		return "", "", fmt.Errorf("patch is not safe to apply: %s", strings.Join(a.ApplySafety.Reasons, "; "))
	}
	original, patched := artifactBodies(a)
	if original == "" || patched == "" || a.OriginalHash == "" || a.PatchedHash == "" {
		return "", "", fmt.Errorf("source-bound method bodies and hashes are required")
	}
	if sha256Hex(original) != a.OriginalHash || sha256Hex(patched) != a.PatchedHash {
		return "", "", fmt.Errorf("artifact method hash mismatch")
	}
	validation := NewSmaliValidator().ValidateStrict(patched)
	if !validation.Valid {
		return "", "", fmt.Errorf("patched method failed validation: %v", validation.Errors)
	}
	if a.BlockPatch != nil {
		if _, _, err := applyBlockPatchDirection(original, a, false); err != nil {
			return "", "", err
		}
	}
	return original, patched, nil
}

func buildArtifact(point *PatchPoint, patch *GeneratedPatch, validation ValidationResult) *PatchArtifact {
	patched := canonicalPatchText(patch.PatchedCode)

	// Issue 5: we must include the method header if it's not present in OriginalCode
	// Actually, point.MethodBody should be used if patch.OriginalCode is truncated.
	// But let's build the full body.
	fullOriginal := strings.Join(point.MethodBody, "\n")
	fullOriginal = canonicalPatchText(fullOriginal)
	if requiresStructurePreservation(patch.PatchType) && fullOriginal != "" {
		structure := preflightBodyStructure(fullOriginal, patched)
		if !structure.Valid {
			validation.Valid = false
			validation.Errors = append(validation.Errors, structure.Errors...)
		}
		validation.Warnings = append(validation.Warnings, structure.Warnings...)
	}

	if err := verifyReturnCoverage(point.MethodBody, patch.ReturnCoverage); err != nil {
		validation.addStructuralError(err.Error())
	}

	// Wait, if patch.OriginalCode was truncated, we shouldn't use it for patching.
	// We'll store fullOriginal for the artifact's OriginalCode so we can replace safely.
	// Wait, the patched code in `GeneratedPatch` might also have the `# ...` if it wasn't generated correctly?
	// No, `buildPatchedCode` regenerates everything from scratch, it doesn't use `point.MethodBody` (except for the header).

	artifact := &PatchArtifact{
		SchemaVersion:   "2.1.0",
		MethodName:      point.MethodName,
		FilePath:        patch.FilePath,
		MethodSignature: point.MethodSignature,
		PatchType:       patch.PatchType,
		OriginalCode:    fullOriginal,
		PatchedCode:     patched,
		OriginalHash:    sha256Hex(fullOriginal),
		PatchedHash:     sha256Hex(patched),
		UnifiedDiff:     buildUnifiedDiff(patch.FilePath, fullOriginal, patched),
		Validation:      validation,
		BlockPatch:      buildBlockPatch(fullOriginal, patched),
	}
	artifact.PatchID = stablePatchID(artifact.FilePath, artifact.MethodName, artifact.MethodSignature, artifact.OriginalHash)
	artifact.ApplySafety = evaluateApplySafety(point, validation)
	if patch.ReturnCoverage != nil {
		coverage := *patch.ReturnCoverage
		artifact.ReturnCoverage = &coverage
	}
	if isPartialForcedPatch(patch) {
		artifact.ApplySafety.Safe = false
		artifact.ApplySafety.CanWrite = false
		if artifact.ApplySafety.Level != "blocked" {
			artifact.ApplySafety.Level = "review"
		}
		artifact.ApplySafety.Reasons = append(artifact.ApplySafety.Reasons, "partial return coverage requires review")
	}
	return artifact
}

func canonicalPatchText(text string) string {
	return strings.ReplaceAll(strings.TrimRight(text, "\r\n"), "\r\n", "\n")
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func evaluateApplySafety(point *PatchPoint, validation ValidationResult) ApplySafety {
	safety := ApplySafety{
		Safe:     validation.Valid,
		Level:    "safe",
		CanWrite: validation.Valid,
	}
	if !validation.Valid {
		safety.Level = "blocked"
		safety.CanWrite = false
		safety.Reasons = append(safety.Reasons, "generated smali failed validation")
	}
	if len(point.MethodBody) == 0 {
		safety.Safe = false
		safety.Level = "blocked"
		safety.CanWrite = false
		safety.Reasons = append(safety.Reasons, "original method body is unavailable")
	}
	for _, warning := range validation.Warnings {
		if strings.Contains(strings.ToLower(warning), "try/catch") {
			safety.Safe = false
			safety.Level = "review"
			safety.CanWrite = false
			safety.Reasons = append(safety.Reasons, warning)
		}
	}
	return safety
}

func buildBlockPatch(original, patched string) *BlockPatch {
	origLines := strings.Split(canonicalPatchText(original), "\n")
	patchedLines := strings.Split(canonicalPatchText(patched), "\n")
	if len(origLines) == 0 || len(patchedLines) == 0 {
		return nil
	}
	first := -1
	max := len(origLines)
	if len(patchedLines) > max {
		max = len(patchedLines)
	}
	for i := 0; i < max; i++ {
		var o, p string
		if i < len(origLines) {
			o = origLines[i]
		}
		if i < len(patchedLines) {
			p = patchedLines[i]
		}
		if o != p {
			first = i
			break
		}
	}
	if first < 0 {
		return nil
	}
	lastOrig := len(origLines) - 1
	lastPatched := len(patchedLines) - 1
	for lastOrig >= first && lastPatched >= first && origLines[lastOrig] == patchedLines[lastPatched] {
		lastOrig--
		lastPatched--
	}
	ctx := 2
	ctxBeforeStart := first - ctx
	if ctxBeforeStart < 0 {
		ctxBeforeStart = 0
	}
	ctxAfterEnd := lastOrig + 1 + ctx
	if ctxAfterEnd > len(origLines) {
		ctxAfterEnd = len(origLines)
	}
	originalBlock := append([]string(nil), origLines[first:lastOrig+1]...)
	patchedBlock := append([]string(nil), patchedLines[first:lastPatched+1]...)
	return &BlockPatch{
		StartLine:     first + 1,
		EndLine:       lastOrig + 1,
		OriginalLines: originalBlock,
		PatchedLines:  patchedBlock,
		OriginalHash:  sha256Hex(strings.Join(originalBlock, "\n")),
		PatchedHash:   sha256Hex(strings.Join(patchedBlock, "\n")),
		ContextBefore: append([]string(nil), origLines[ctxBeforeStart:first]...),
		ContextAfter:  append([]string(nil), origLines[lastOrig+1:ctxAfterEnd]...),
	}
}
