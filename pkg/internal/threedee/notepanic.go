package threedee

import "mega-analyzer/pkg/internal/panicnote"

// notePanic makes deliberately recovered parser panics visible instead of
// silently dropping them. See package panicnote.
func notePanic(stage string, r any) { panicnote.Note(stage, r) }
