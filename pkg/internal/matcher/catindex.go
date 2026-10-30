package matcher

import (
	"mega-analyzer/pkg/internal/types"
)

// ===============================================================================
// CATEGORY INDEX
//
// The hot line-scanning loop used to key three separate maps by types.Category
// (a string): the per-file counter, the per-file limit table and the global cap
// counter (a sync.Map). Profiling a full APK scan showed 16.6% of all CPU in
// isGlobalCapReached alone, dominated by string hashing (aeshashbody) and map
// probes -- pure bookkeeping, no matching work.
//
// Every category that can appear on a compiled pattern is known at process
// start, so each one gets a dense integer id once and the hot loop indexes
// slices instead of hashing strings. Categories missing from the registry
// (patterns built at runtime) keep working through the map-based fallback.
// ===============================================================================

var (
	catIDs           map[types.Category]int32
	catNames         []types.Category
	catGlobalCapByID []int64
	catFileLimitByID []int32
)

func init() {
	catIDs = make(map[types.Category]int32, 192)

	register := func(c types.Category) {
		if _, ok := catIDs[c]; ok {
			return
		}
		catIDs[c] = int32(len(catNames))
		catNames = append(catNames, c)
	}

	defs := GetAllPatterns()
	for i := range defs {
		register(defs[i].Category)
	}
	for c := range globalCategoryCaps {
		register(c)
	}
	for c := range maxPerCategoryPerFile {
		register(c)
	}

	catGlobalCapByID = make([]int64, len(catNames))
	catFileLimitByID = make([]int32, len(catNames))
	for i, c := range catNames {
		capVal := defaultGlobalCap
		if v, ok := globalCategoryCaps[c]; ok {
			capVal = v
		}
		catGlobalCapByID[i] = int64(capVal)

		limit := defaultMaxPerCatFile
		if v, ok := maxPerCategoryPerFile[c]; ok {
			limit = v
		}
		catFileLimitByID[i] = int32(limit)
	}
}

// categoryID returns the dense id of a category, or -1 when the category was
// not known at startup.
func categoryID(c types.Category) int32 {
	if id, ok := catIDs[c]; ok {
		return id
	}
	return -1
}

// numCategories is the size every per-category slice must have.
func numCategories() int { return len(catNames) }

// catScratch holds the per-file (or per-chunk) category bookkeeping that used
// to live in two maps. Lookups are array indexing; starting a new line costs
// one generation increment instead of clearing a map.
type catScratch struct {
	fileCount []int32
	seenGen   []uint32
	gen       uint32

	// Fallback for categories missing from the registry.
	fileCountMap map[types.Category]int
	seenMap      map[types.Category]struct{}
}

func newCatScratch() *catScratch {
	n := numCategories()
	return &catScratch{
		fileCount: make([]int32, n),
		seenGen:   make([]uint32, n),
	}
}

// nextLine starts a new line: every category becomes unseen again.
func (s *catScratch) nextLine() {
	s.gen++
	if s.gen == 0 {
		// Wrapped: reset explicitly so stale generations cannot alias.
		for i := range s.seenGen {
			s.seenGen[i] = 0
		}
		s.gen = 1
	}
	if s.seenMap != nil {
		clear(s.seenMap)
	}
}

// blocked reports whether this category must be skipped on the current line,
// either because it already matched here or because the per-file limit is
// spent. Same precedence as the original map code.
func (s *catScratch) blocked(id int32, cat types.Category) bool {
	if id >= 0 && int(id) < len(s.fileCount) {
		if s.seenGen[id] == s.gen {
			return true
		}
		return s.fileCount[id] >= catFileLimitByID[id]
	}

	if s.seenMap != nil {
		if _, seen := s.seenMap[cat]; seen {
			return true
		}
	}
	limit := defaultMaxPerCatFile
	if v, ok := maxPerCategoryPerFile[cat]; ok {
		limit = v
	}
	return s.fileCountMap[cat] >= limit
}

// record marks a match for this category on the current line.
func (s *catScratch) record(id int32, cat types.Category) {
	if id >= 0 && int(id) < len(s.fileCount) {
		s.seenGen[id] = s.gen
		s.fileCount[id]++
		return
	}
	if s.seenMap == nil {
		s.seenMap = make(map[types.Category]struct{}, 4)
		s.fileCountMap = make(map[types.Category]int, 4)
	}
	s.seenMap[cat] = struct{}{}
	s.fileCountMap[cat]++
}
