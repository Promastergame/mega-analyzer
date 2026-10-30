package secrets

import "sort"

// lineIndex precomputes newline offsets so per-finding line/column lookups
// cost O(log n) instead of rescanning the text for every match (the old
// per-finding LineCol walk made DetectProviders quadratic on match-heavy
// inputs).
type lineIndex struct {
	starts []int // byte offset of the first character of each line
}

func buildLineIndex(text string) *lineIndex {
	starts := make([]int, 1, 64) // starts[0] == 0: line 1 begins at offset 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

// lineCol mirrors LineCol semantics: 1-based line and 1-based byte column.
func (ix *lineIndex) lineCol(offset int) (int, int) {
	i := sort.SearchInts(ix.starts, offset+1) - 1
	if i < 0 {
		i = 0
	}
	return i + 1, offset - ix.starts[i] + 1
}
