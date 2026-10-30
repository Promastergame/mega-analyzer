package ml

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ApplyArtifact applies one validated artifact. For untrusted/project-relative
// artifacts prefer ApplyArtifactToBase so path containment can be enforced.
func ApplyArtifact(artifact *PatchArtifact) error {
	return ApplyArtifactToBase("", artifact)
}

// ApplyArtifactToBase applies a patch without allowing the artifact to escape
// baseDir. Application is idempotent and prefers a minimal block replacement.
func ApplyArtifactToBase(baseDir string, artifact *PatchArtifact) error {
	return mutateArtifact(baseDir, artifact, false)
}

// RevertArtifactToBase reverses only this artifact. It never restores the whole
// .original file, so unrelated edits and independently applied patches survive.
func RevertArtifactToBase(baseDir string, artifact *PatchArtifact) error {
	return mutateArtifact(baseDir, artifact, true)
}

// ApplyArtifactToBaseWithResult reports whether the operation wrote a change.
// Already-applied artifacts succeed with changed=false.
func ApplyArtifactToBaseWithResult(baseDir string, artifact *PatchArtifact) (bool, error) {
	return mutateArtifactChanged(baseDir, artifact, false)
}

func mutateArtifact(baseDir string, artifact *PatchArtifact, reverse bool) error {
	_, err := mutateArtifactChanged(baseDir, artifact, reverse)
	return err
}

func mutateArtifactChanged(baseDir string, artifact *PatchArtifact, reverse bool) (bool, error) {
	if artifact == nil {
		return false, fmt.Errorf("patch artifact is nil")
	}
	if !reverse && !artifact.ApplySafety.CanWrite {
		return false, fmt.Errorf("patch is not safe to apply: %s", strings.Join(artifact.ApplySafety.Reasons, "; "))
	}
	targetPath, err := resolveArtifactTarget(baseDir, artifact.FilePath)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		return false, fmt.Errorf("stat target file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("target is not a regular file: %s", targetPath)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return false, fmt.Errorf("read target file: %w", err)
	}

	lineEnding := "\n"
	if strings.Contains(string(data), "\r\n") {
		lineEnding = "\r\n"
	}
	hadTrailingNewline := strings.HasSuffix(string(data), "\n")
	content := canonicalPatchText(string(data))
	original, patched := artifactBodies(artifact)
	if reverse {
		original, patched = patched, original
	}
	if original == "" || patched == "" {
		return false, fmt.Errorf("artifact does not contain method bodies")
	}

	expectedOriginalHash, expectedPatchedHash := artifact.OriginalHash, artifact.PatchedHash
	if reverse {
		expectedOriginalHash, expectedPatchedHash = expectedPatchedHash, expectedOriginalHash
	}
	if expectedOriginalHash != "" && sha256Hex(original) != expectedOriginalHash {
		return false, fmt.Errorf("artifact source hash mismatch")
	}
	if expectedPatchedHash != "" && sha256Hex(patched) != expectedPatchedHash {
		return false, fmt.Errorf("artifact destination hash mismatch")
	}

	updated, appliedByBlock, err := applyBlockPatchDirection(content, artifact, reverse)
	if err != nil {
		return false, err
	}
	if !appliedByBlock {
		updated, err = replaceUniqueMethodBody(content, original, patched, targetPath)
		if err != nil {
			return false, err
		}
	}
	if updated == content { // already in requested state
		return false, nil
	}

	backupPath := targetPath + ".original"
	if backupInfo, err := os.Lstat(backupPath); os.IsNotExist(err) {
		if err := writeFileAtomic(backupPath, data, info.Mode().Perm()); err != nil {
			return false, fmt.Errorf("create backup file: %w", err)
		}
	} else if err != nil {
		return false, fmt.Errorf("stat backup file: %w", err)
	} else if !backupInfo.Mode().IsRegular() {
		return false, fmt.Errorf("backup is not a regular file: %s", backupPath)
	}

	styled := restoreTextStyle(updated, lineEnding, hadTrailingNewline)
	if err := writeFileAtomic(targetPath, []byte(styled), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("write patched file: %w", err)
	}
	return true, nil
}

func artifactBodies(artifact *PatchArtifact) (string, string) {
	if artifact.OriginalCode != "" && artifact.PatchedCode != "" {
		return canonicalPatchText(artifact.OriginalCode), canonicalPatchText(artifact.PatchedCode)
	}
	return canonicalPatchText(extractOriginalFromUnifiedDiff(artifact.UnifiedDiff)), canonicalPatchText(extractPatchedFromUnifiedDiff(artifact.UnifiedDiff))
}

func resolveArtifactTarget(baseDir, artifactPath string) (string, error) {
	if strings.TrimSpace(artifactPath) == "" || strings.ContainsRune(artifactPath, '\x00') {
		return "", fmt.Errorf("invalid artifact file path")
	}
	normalizedArtifact := strings.ReplaceAll(artifactPath, "\\", "/")
	if strings.HasPrefix(normalizedArtifact, "/") || strings.Contains(strings.Split(normalizedArtifact, "/")[0], ":") {
		if baseDir != "" {
			return "", fmt.Errorf("absolute artifact path is not allowed with a base directory: %s", artifactPath)
		}
	}
	cleanArtifact := filepath.Clean(filepath.FromSlash(normalizedArtifact))
	if baseDir == "" {
		return cleanArtifact, nil
	}
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve base directory: %w", err)
	}
	candidate := cleanArtifact
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(baseAbs, candidate)
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve artifact path: %w", err)
	}
	rel, err := filepath.Rel(baseAbs, candidateAbs)
	if err != nil {
		return "", fmt.Errorf("check artifact path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("artifact path escapes base directory: %s", artifactPath)
	}
	// Reject a symlink/junction target that resolves outside the trusted tree.
	resolvedBase, err := filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return "", fmt.Errorf("resolve base symlinks: %w", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(candidateAbs)
	if err != nil {
		return "", fmt.Errorf("resolve artifact symlinks: %w", err)
	}
	resolvedRel, err := filepath.Rel(resolvedBase, resolvedTarget)
	if err != nil || resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) || filepath.IsAbs(resolvedRel) {
		return "", fmt.Errorf("artifact symlink target escapes base directory: %s", artifactPath)
	}
	return candidateAbs, nil
}

func replaceUniqueMethodBody(content, original, patched, targetPath string) (string, error) {
	originalCount := strings.Count(content, original)
	if originalCount == 1 {
		return strings.Replace(content, original, patched, 1), nil
	}
	if originalCount > 1 {
		return "", fmt.Errorf("original method context is ambiguous in %s", targetPath)
	}
	if strings.Count(content, patched) == 1 {
		return content, nil
	}
	return "", fmt.Errorf("original method context not found in %s", targetPath)
}

// extractOriginalFromUnifiedDiff provides backwards compatibility for old artifacts.
func extractOriginalFromUnifiedDiff(diff string) string { return extractUnifiedBody(diff, '-') }
func extractPatchedFromUnifiedDiff(diff string) string  { return extractUnifiedBody(diff, '+') }

func extractUnifiedBody(diff string, prefix byte) string {
	lines := strings.Split(diff, "\n")
	body := make([]string, 0, len(lines))
	inHunk := false
	for _, line := range lines {
		if strings.HasPrefix(line, "@@") {
			inHunk = true
			continue
		}
		if !inHunk || line == "" {
			continue
		}
		switch line[0] {
		case prefix, ' ':
			body = append(body, line[1:])
		}
	}
	return strings.Join(body, "\n")
}

func applyBlockPatchDirection(content string, artifact *PatchArtifact, reverse bool) (string, bool, error) {
	bp := artifact.BlockPatch
	if bp == nil {
		return "", false, nil
	}
	original, patched := artifactBodies(artifact)
	expected := buildBlockPatch(original, patched)
	// Independent hashes are not enough: a block with its own valid hashes
	// must still describe the edit authorized by the full method bodies.
	if expected == nil || !slices.Equal(bp.OriginalLines, expected.OriginalLines) || !slices.Equal(bp.PatchedLines, expected.PatchedLines) {
		return "", true, fmt.Errorf("artifact block does not match method bodies")
	}
	if (len(bp.ContextBefore) > 0 && !slices.Equal(bp.ContextBefore, expected.ContextBefore)) ||
		(len(bp.ContextAfter) > 0 && !slices.Equal(bp.ContextAfter, expected.ContextAfter)) {
		return "", true, fmt.Errorf("artifact block context does not match method bodies")
	}
	sourceLines, destinationLines := bp.OriginalLines, bp.PatchedLines
	sourceHash, destinationHash := bp.OriginalHash, bp.PatchedHash
	if reverse {
		sourceLines, destinationLines = destinationLines, sourceLines
		sourceHash, destinationHash = destinationHash, sourceHash
	}
	if sourceHash != "" && sha256Hex(strings.Join(sourceLines, "\n")) != sourceHash {
		return "", true, fmt.Errorf("artifact block source hash mismatch")
	}
	if destinationHash != "" && sha256Hex(strings.Join(destinationLines, "\n")) != destinationHash {
		return "", true, fmt.Errorf("artifact block destination hash mismatch")
	}

	// Empty-sided edits cannot be located uniquely by a block search. Use an
	// exact full-method replacement in both directions (including deletion undo).
	if len(sourceLines) == 0 || len(destinationLines) == 0 {
		return "", false, nil
	}
	methodLines := strings.Split(original, "\n")
	if len(methodLines) == 0 || strings.TrimSpace(methodLines[0]) == "" {
		return "", false, nil
	}
	methodHeader := strings.TrimSpace(methodLines[0])
	if methodHeader != strings.TrimSpace(strings.Split(patched, "\n")[0]) {
		return "", false, nil // changed header requires exact full-method matching
	}
	fileLines := strings.Split(content, "\n")
	methodStart, methodEnd, err := uniqueMethodBounds(fileLines, methodHeader)
	if err != nil {
		return "", true, err
	}
	if methodStart < 0 {
		// A reverse operation may carry a patched header that is identical in
		// practice; full-method fallback will provide the final diagnosis.
		return "", false, nil
	}

	// Exact method matching takes precedence over a repeated changed line.
	// Block metadata was checked above even when the complete method matches.
	sourceBody, destinationBody := original, patched
	if reverse {
		sourceBody, destinationBody = destinationBody, sourceBody
	}
	currentBody := strings.Join(fileLines[methodStart:methodEnd+1], "\n")
	if currentBody == destinationBody {
		return content, true, nil
	}
	if currentBody == sourceBody {
		updated := append([]string(nil), fileLines[:methodStart]...)
		updated = append(updated, strings.Split(destinationBody, "\n")...)
		updated = append(updated, fileLines[methodEnd+1:]...)
		return strings.Join(updated, "\n"), true, nil
	}

	// Derive anchors from the authoritative bodies, including for legacy
	// artifacts that did not serialize ContextBefore/ContextAfter.
	start, state := locateAnchoredBlock(fileLines, methodStart, methodEnd, sourceLines, sourceHash, expected.ContextBefore, expected.ContextAfter)
	if state == "ambiguous" {
		return "", true, fmt.Errorf("block patch context is ambiguous in %s", artifact.FilePath)
	}
	if state == "missing" {
		if _, already := locateAnchoredBlock(fileLines, methodStart, methodEnd, destinationLines, destinationHash, expected.ContextBefore, expected.ContextAfter); already == "found" {
			return content, true, nil
		}
		return "", true, fmt.Errorf("block patch context drifted in %s", artifact.FilePath)
	}
	end := start + len(sourceLines)
	updatedLines := make([]string, 0, len(fileLines)-len(sourceLines)+len(destinationLines))
	updatedLines = append(updatedLines, fileLines[:start]...)
	updatedLines = append(updatedLines, destinationLines...)
	updatedLines = append(updatedLines, fileLines[end:]...)
	return strings.Join(updatedLines, "\n"), true, nil
}

func uniqueMethodBounds(lines []string, header string) (int, int, error) {
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			if start >= 0 {
				return -1, -1, fmt.Errorf("method header is ambiguous: %s", header)
			}
			start = i
		}
	}
	if start < 0 {
		return -1, -1, nil
	}
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if i > start && strings.HasPrefix(trimmed, ".method ") {
			return -1, -1, fmt.Errorf("nested method before end of %s", header)
		}
		if trimmed == ".end method" {
			return start, i, nil
		}
	}
	return -1, -1, fmt.Errorf("method end not found for %s", header)
}

func locateUniqueBlock(lines []string, methodStart, methodEnd int, block []string, expectedHash string) (int, string) {
	return locateAnchoredBlock(lines, methodStart, methodEnd, block, expectedHash, nil, nil)
}

func locateAnchoredBlock(lines []string, methodStart, methodEnd int, block []string, expectedHash string, before, after []string) (int, string) {
	if len(block) == 0 || methodStart < 0 || methodEnd >= len(lines) || methodStart > methodEnd {
		return -1, "missing"
	}
	found := -1
	last := methodEnd - len(block) + 1
	for i := methodStart; i <= last; i++ {
		candidate := strings.Join(lines[i:i+len(block)], "\n")
		matches := candidate == strings.Join(block, "\n")
		if !matches && expectedHash != "" {
			matches = sha256Hex(candidate) == expectedHash
		}
		if matches && blockContextMatches(lines, methodStart, methodEnd, i, len(block), before, after) {
			if found >= 0 {
				return -1, "ambiguous"
			}
			found = i
		}
	}
	if found < 0 {
		return -1, "missing"
	}
	return found, "found"
}

// Comments and blank lines outside an edit may drift without changing its
// executable anchor. Other changes to the adjacent context require review.
func blockContextMatches(lines []string, methodStart, methodEnd, start, size int, before, after []string) bool {
	ignorable := func(line string) bool {
		line = strings.TrimSpace(line)
		return line == "" || strings.HasPrefix(line, "#")
	}
	i := start - 1
	for j := len(before) - 1; j >= 0; j-- {
		if ignorable(before[j]) {
			continue
		}
		for i >= methodStart && ignorable(lines[i]) {
			i--
		}
		if i < methodStart || lines[i] != before[j] {
			return false
		}
		i--
	}
	i = start + size
	for _, line := range after {
		if ignorable(line) {
			continue
		}
		for i <= methodEnd && ignorable(lines[i]) {
			i++
		}
		if i > methodEnd || lines[i] != line {
			return false
		}
		i++
	}
	return true
}

func restoreTextStyle(canonical, lineEnding string, trailing bool) string {
	canonical = strings.TrimRight(canonical, "\n")
	if lineEnding == "\r\n" {
		canonical = strings.ReplaceAll(canonical, "\n", "\r\n")
	}
	if trailing {
		canonical += lineEnding
	}
	return canonical
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeFileAtomicWithRename(path, data, mode, os.Rename)
}

// The rename dependency permits deterministic failure tests without mutable
// package globals. A failed replacement must never truncate the destination.
func writeFileAtomicWithRename(path string, data []byte, mode os.FileMode, rename func(string, string) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mega-patch-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rename(tmpName, path); err != nil {
		// Fail closed on sharing violations or filesystems that cannot replace
		// an existing file. A backup does not make a truncating write atomic.
		return fmt.Errorf("replace target file: %w", err)
	}
	return nil
}
