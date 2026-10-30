package media

import (
	"fmt"
	"sort"
	"strings"
)

// warnings: mediaWarning, warnBag, safeStage.
//
// Split from exif.go: exact code move, no logic changes.

// --- Warnings ---------------------------------------------------------------

// mediaWarning is a machine-readable parse defect. Codes, not prose: you
// cannot alert on or write a test against a human sentence.
type mediaWarning struct {
	Stage  string // "jpeg.walk", "tiff.ifd0", "png.chunks"
	Code   string // "malformed_segment", "offset_out_of_bounds", "panic"
	Offset int64  // -1 when not positional
	Detail string
}

func (w mediaWarning) String() string {
	s := w.Stage + ":" + w.Code
	if w.Offset >= 0 {
		s += fmt.Sprintf("@%d", w.Offset)
	}
	if w.Detail != "" {
		s += " (" + w.Detail + ")"
	}
	return s
}

// warnBag collects warnings with a hard cap, so a file engineered to produce
// one warning per byte cannot exhaust memory through the error path.
type warnBag struct {
	list    []mediaWarning
	dropped int
}

const maxWarnings = 64

func (w *warnBag) add(stage, code string, off int64, detail string) {
	if w == nil {
		return
	}
	if len(w.list) >= maxWarnings {
		w.dropped++
		return
	}
	w.list = append(w.list, mediaWarning{Stage: stage, Code: code, Offset: off, Detail: detail})
}

// summary renders a stable, deduplicated "stage:code" list for the flat
// Fields map. Sorted, so two runs over the same bytes produce byte-identical
// output and a report can be hashed.
func (w *warnBag) summary() string {
	if w == nil || len(w.list) == 0 {
		return ""
	}
	seen := make(map[string]int, len(w.list))
	for _, x := range w.list {
		seen[x.Stage+":"+x.Code]++
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if seen[k] > 1 {
			parts = append(parts, fmt.Sprintf("%s x%d", k, seen[k]))
		} else {
			parts = append(parts, k)
		}
	}
	if w.dropped > 0 {
		parts = append(parts, fmt.Sprintf("(+%d more suppressed)", w.dropped))
	}
	return strings.Join(parts, ", ")
}

// safeStage runs one sub-extraction and turns a panic into a warning instead
// of losing everything else.
//
// A recovered panic is a BUG REPORT, not a correctness mechanism: the fuzz
// invariant is that stage "panic" warnings never appear. Bare recover() with
// nowhere to record it is how a parser stays broken for a whole class of
// files without anyone finding out.
func safeStage(w *warnBag, stage string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			w.add(stage, "panic", -1, fmt.Sprint(r))
		}
	}()
	fn()
}
