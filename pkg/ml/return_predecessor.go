package ml

import "strings"

// straightLinePredecessors returns the previous executable instruction only
// when there is no intervening basic-block entry/exit. Textual proximity is not
// a reaching-definition proof: a label or numeric branch can enter at return
// and bypass a lexically preceding const. Unknown numeric layouts fail closed.
func straightLinePredecessors(body []string) []int {
	out := make([]int, len(body))
	for i := range out {
		out[i] = -1
	}
	entries, known := numericBranchEntryLines(body)
	if !known {
		return out
	}
	previous := -1
	var state smaliNonCodeState
	for i, raw := range body {
		line := smaliCodeLine(raw)
		if state.skip(line) {
			previous = -1
			continue
		}
		if entries[i] || strings.HasPrefix(line, ":") || hasSmaliDirective(line, ".catch") || hasSmaliDirective(line, ".catchall") {
			previous = -1
		}
		out[i] = previous
		if op, ok := insnLine(line); ok {
			previous = i
			if isControlTransfer(op) {
				previous = -1
			}
		}
	}
	return out
}

func isControlTransfer(op string) bool {
	return strings.HasPrefix(op, "if-") || strings.HasPrefix(op, "goto") ||
		strings.HasPrefix(op, "return") || op == "throw" ||
		op == "packed-switch" || op == "sparse-switch"
}

func numericBranchEntryLines(body []string) (map[int]bool, bool) {
	entries := make(map[int]bool)
	if !hasNumericBranch(body) {
		return entries, true
	}
	if hasRelayoutHazard(body) {
		return nil, false
	}
	byOffset := make(map[int]int)
	targets := []int{}
	offset := 0
	var state smaliNonCodeState
	for i, raw := range body {
		line := smaliCodeLine(raw)
		if state.skip(line) {
			continue
		}
		op, ok := insnLine(line)
		if !ok {
			continue
		}
		units, known := smaliUnits(op)
		if !known {
			return nil, false
		}
		byOffset[offset] = i
		if _, branch := branchRangeOK(op); branch {
			if delta, numeric := parseTrailingOffset(line); numeric {
				targets = append(targets, offset+delta)
			}
		}
		offset += units
	}
	for _, target := range targets {
		line, ok := byOffset[target]
		if !ok {
			return nil, false
		}
		entries[line] = true
	}
	return entries, true
}

// entryDefinitionDominates proves only the inexpensive entry-block case:
// before this sole definition there is no branch, return or block entry, and
// the target return follows it. Exceptions/payloads/unknown layouts abstain.
// This retains safe single-def swaps without equating uniqueness to dominance.
func entryDefinitionDominates(body []string, defLine, returnLine int) bool {
	if defLine < 0 || defLine >= returnLine || returnLine >= len(body) || hasRelayoutHazard(body) {
		return false
	}
	var state smaliNonCodeState
	for _, raw := range body[:defLine] {
		line := smaliCodeLine(raw)
		if state.skip(line) || strings.HasPrefix(line, ":") {
			return false
		}
		if op, ok := insnLine(line); ok && isControlTransfer(op) {
			return false
		}
	}
	return true
}
