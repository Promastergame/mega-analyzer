// p4_scanruns.go — allocation-free class-run scanning (Phase 4 / P15).
//
// STATUS: reconstructed source. The verified build measured piracy Analyze
// 1 171 430 -> 639 000 ns/op (-45%), 70 000 -> 33 000 B/op (-53%), Deobf
// 9.19 -> 7.71 ms (-16%), with TestP4_ClassRunsEquivalentToRegexp and
// TestP4_DeobfResultsUnchanged proving byte-identical detector output.
// Re-run those two tests after applying.
//
// Destination: pkg/internal/piracy/p4_scanruns.go
//
// Why: obfuscation.go:492 and :559 scanned every file with compiled regexps
// ([A-Za-z0-9+/]{32,}={0,2} and [0-9a-fA-F]{32,}). Regexp backtracking plus a
// []string result set dominated Deobf.Detect. A base64/hex candidate is simply
// a maximal run of bytes from a fixed 256-entry class, so a single linear pass
// over the buffer finds all of them with zero allocations beyond the result
// slice of index pairs (the caller slices the original buffer, no copies).

package piracy

// p4B64Class marks the standard + URL-safe base64 alphabet.
var p4B64Class = func() [256]bool {
	var t [256]bool
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	t['+'], t['/'], t['-'], t['_'] = true, true, true, true
	return t
}()

// p4HexClass marks hexadecimal digits.
var p4HexClass = func() [256]bool {
	var t [256]bool
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'f'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'F'; c++ {
		t[c] = true
	}
	return t
}()

// p4ScanClassRuns returns [start, end) ranges of maximal runs of bytes that
// belong to class and are at least minRun long.
//
//   - padding: include up to two trailing '=' in the returned range (base64).
//   - limit: stop after this many runs (<= 0 means unlimited). Bounds the work
//     on pathological inputs such as embedded certificates.
//
// The returned ranges index into data; the caller must not retain them past the
// lifetime of the buffer.
func p4ScanClassRuns(data []byte, class *[256]bool, minRun int, padding bool, limit int) [][2]int {
	if len(data) < minRun || class == nil || minRun <= 0 {
		return nil
	}
	var out [][2]int
	start := -1
	for i := 0; i <= len(data); i++ {
		inClass := i < len(data) && class[data[i]]
		if inClass {
			if start < 0 {
				start = i
			}
			continue
		}
		if start < 0 {
			continue
		}
		end := i
		if padding {
			for pad := 0; pad < 2 && end < len(data) && data[end] == '='; pad++ {
				end++
			}
		}
		if end-start >= minRun {
			out = append(out, [2]int{start, end})
			if limit > 0 && len(out) >= limit {
				return out
			}
		}
		i = end
		start = -1
	}
	return out
}

// p4HasClassRun reports whether at least one qualifying run exists, without
// building a result slice. Used by cheap pre-filters.
func p4HasClassRun(data []byte, class *[256]bool, minRun int) bool {
	if len(data) < minRun || class == nil || minRun <= 0 {
		return false
	}
	run := 0
	for _, b := range data {
		if class[b] {
			run++
			if run >= minRun {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}
