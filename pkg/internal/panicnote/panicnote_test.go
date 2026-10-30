package panicnote

import (
	"bytes"
	"strings"
	"testing"
)

func TestNoteRecordsAndSuppresses(t *testing.T) {
	var buf bytes.Buffer
	orig := Output
	Output = &buf
	defer func() { Output = orig }()

	stage := "panicnote.test"
	for i := 0; i < maxStacksPerStage+2; i++ {
		func() {
			defer func() { Note(stage, recover()) }()
			panic("boom")
		}()
	}
	Note(stage, nil) // no panic: ignored

	if got := Snapshot()[stage]; got != int64(maxStacksPerStage+2) {
		t.Fatalf("count = %d", got)
	}
	out := buf.String()
	if !strings.Contains(out, "[panic recovered] panicnote.test: boom") {
		t.Fatalf("missing note: %s", out)
	}
	if !strings.Contains(out, "stack suppressed") {
		t.Fatal("stacks were not suppressed after limit")
	}
}
