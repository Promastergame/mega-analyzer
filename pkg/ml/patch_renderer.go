package ml

import (
	"fmt"
	"strings"
)

// buildDiffView formats a diff view for the UI and Terminal.
// Issue 4: It truncates large blocks of removed lines to prevent bloated reports.
func buildDiffView(patch *GeneratedPatch) string {
	var b strings.Builder

	origLines := strings.Split(patch.OriginalCode, "\n")
	patchLines := strings.Split(patch.PatchedCode, "\n")

	// Header
	b.WriteString(fmt.Sprintf("--- a/%s (original)\n", patch.FilePath))
	b.WriteString(fmt.Sprintf("+++ b/%s (patched)\n", patch.FilePath))
	b.WriteString(fmt.Sprintf("@@ method: %s @@\n", patch.MethodName))

	// Method header (not changed)
	if len(origLines) > 0 && len(patchLines) > 0 {
		b.WriteString(" ")
		b.WriteString(origLines[0])
		b.WriteString("\n")
	}

	// Removed lines (original)
	maxRemovedToShow := 10
	removedCount := len(origLines) - 2 // exclude header and footer

	if removedCount > maxRemovedToShow {
		half := maxRemovedToShow / 2
		for i := 1; i <= half; i++ {
			b.WriteString("-")
			b.WriteString(origLines[i])
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("-    # ... (%d lines removed) ...\n", removedCount-maxRemovedToShow))
		for i := len(origLines) - 1 - half; i < len(origLines)-1; i++ {
			b.WriteString("-")
			b.WriteString(origLines[i])
			b.WriteString("\n")
		}
	} else {
		for i := 1; i < len(origLines)-1; i++ {
			b.WriteString("-")
			b.WriteString(origLines[i])
			b.WriteString("\n")
		}
	}

	// Added lines (patched)
	for i := 1; i < len(patchLines)-1; i++ {
		b.WriteString("+")
		b.WriteString(patchLines[i])
		b.WriteString("\n")
	}

	// Footer
	b.WriteString(" .end method\n")

	return b.String()
}

// buildMarkdownBlock creates a markdown formatted code block
func buildMarkdownBlock(code string, lang string) string {
	return fmt.Sprintf("```%s\n%s\n```", lang, code)
}

// FormatForTerminal formats the patch for terminal output
func FormatForTerminal(patch *GeneratedPatch) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  ┌─── ORIGINAL (%d lines) ────────────────────────┐\n",
		patch.OriginalLines))

	origLines := strings.Split(patch.OriginalCode, "\n")
	if len(origLines) > 15 {
		for i := 0; i < 7; i++ {
			line := origLines[i]
			if len(line) > 55 {
				line = line[:52] + "..."
			}
			b.WriteString(fmt.Sprintf("  │ %-55s│\n", line))
		}
		b.WriteString(fmt.Sprintf("  │ ... (%d lines omitted) %-31s│\n", len(origLines)-15, ""))
		for i := len(origLines) - 8; i < len(origLines); i++ {
			line := origLines[i]
			if len(line) > 55 {
				line = line[:52] + "..."
			}
			b.WriteString(fmt.Sprintf("  │ %-55s│\n", line))
		}
	} else {
		for _, line := range origLines {
			if len(line) > 55 {
				line = line[:52] + "..."
			}
			b.WriteString(fmt.Sprintf("  │ %-55s│\n", line))
		}
	}

	b.WriteString("  └────────────────────────────────────────────────────┘\n")
	b.WriteString("                        ↓\n")
	b.WriteString(fmt.Sprintf("  ┌─── PATCHED (%d lines) ─────────────────────────┐\n",
		patch.PatchedLines))

	for _, line := range strings.Split(patch.PatchedCode, "\n") {
		if len(line) > 55 {
			line = line[:52] + "..."
		}
		b.WriteString(fmt.Sprintf("  │ %-55s│\n", line))
	}

	b.WriteString("  └────────────────────────────────────────────────────┘\n")

	return b.String()
}

func buildUnifiedDiff(filePath, original, patched string) string {
	origLines := strings.Split(original, "\n")
	patchLines := strings.Split(patched, "\n")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("--- a/%s\n", filePath))
	b.WriteString(fmt.Sprintf("+++ b/%s\n", filePath))
	b.WriteString(fmt.Sprintf("@@ -1,%d +1,%d @@\n", len(origLines), len(patchLines)))

	// Machine-readable diffs must be lossless and agree with the hunk counts.
	// Presentation-only truncation belongs in buildDiffView/FormatForTerminal.
	for _, line := range origLines {
		b.WriteString("-")
		b.WriteString(line)
		b.WriteByte('\n')
	}

	for _, line := range patchLines {
		b.WriteString("+")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
