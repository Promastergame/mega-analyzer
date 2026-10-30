package ml

import (
	"fmt"
	"strings"
)

// FormatUnifiedDiffForTerminal renders a compact, symmetric unified diff for the
// terminal. The legacy box view truncated the ORIGINAL block but printed the
// PATCHED block in full, so a one-line change looked like a whole-method
// rewrite. This shows a few lines of shared context and marks only the lines
// that actually changed with - / +, making the real edit obvious.
func FormatUnifiedDiffForTerminal(patch *GeneratedPatch) string {
	if patch == nil {
		return ""
	}
	orig := splitLinesNormalized(patch.OriginalCode)
	patched := splitLinesNormalized(patch.PatchedCode)

	// Longest common prefix.
	pre := 0
	for pre < len(orig) && pre < len(patched) && orig[pre] == patched[pre] {
		pre++
	}
	// Longest common suffix that does not overlap the prefix.
	suf := 0
	for suf < len(orig)-pre && suf < len(patched)-pre &&
		orig[len(orig)-1-suf] == patched[len(patched)-1-suf] {
		suf++
	}

	removed := orig[pre : len(orig)-suf]
	added := patched[pre : len(patched)-suf]

	var b strings.Builder
	add := func(s string) { fmt.Fprintln(&b, s) }

	add(fmt.Sprintf("  +- unified diff (%d -> %d lines, changed only) -+", patch.OriginalLines, patch.PatchedLines))

	const ctx = 3
	ctxStart := pre - ctx
	if ctxStart < 0 {
		ctxStart = 0
	}
	if pre > 0 {
		if ctxStart > 0 {
			add(fmt.Sprintf("  | ... %d unchanged line(s) above", ctxStart))
		}
		for i := ctxStart; i < pre; i++ {
			add("  |   " + clipDiffLine(orig[i]))
		}
	}

	if len(removed) == 0 && len(added) == 0 {
		add("  |   (no textual change - method body preserved)")
	}

	const maxChanged = 30
	shownRemoved := removed
	if len(shownRemoved) > maxChanged {
		shownRemoved = shownRemoved[:maxChanged]
	}
	for _, ln := range shownRemoved {
		add("  | - " + clipDiffLine(ln))
	}
	if len(removed) > maxChanged {
		add(fmt.Sprintf("  | - ... %d more removed line(s)", len(removed)-maxChanged))
	}

	shownAdded := added
	if len(shownAdded) > maxChanged {
		shownAdded = shownAdded[:maxChanged]
	}
	for _, ln := range shownAdded {
		add("  | + " + clipDiffLine(ln))
	}
	if len(added) > maxChanged {
		add(fmt.Sprintf("  | + ... %d more added line(s)", len(added)-maxChanged))
	}

	if suf > 0 {
		end := len(orig)
		ctxEnd := len(orig) - suf + ctx
		if ctxEnd > end {
			ctxEnd = end
		}
		for i := len(orig) - suf; i < ctxEnd; i++ {
			add("  |   " + clipDiffLine(orig[i]))
		}
		if end-ctxEnd > 0 {
			add(fmt.Sprintf("  | ... %d unchanged line(s) below", end-ctxEnd))
		}
	}

	b.WriteString("  +----------------------------------------------+")
	return b.String()
}

// splitLinesNormalized splits code into lines, tolerating CRLF and a trailing
// newline so prefix/suffix matching is stable.
func splitLinesNormalized(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// clipDiffLine trims indentation and clamps a line to a terminal-friendly width
// without splitting a multi-byte rune.
func clipDiffLine(s string) string {
	s = strings.TrimRight(s, " \t")
	s = strings.TrimLeft(s, " \t")
	r := []rune(s)
	const max = 66
	if len(r) > max {
		return string(r[:max-1]) + "..."
	}
	return s
}
