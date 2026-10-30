package main

import (
	"testing"
	"time"

	"mega-analyzer/pkg/ncer"
)

func TestFeedNcerMitmCapture_StubOrLinkedIsSafe(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	var logged []string
	emit := func(ev TelemetryEvent) { logged = append(logged, ev.Details) }

	feedNcerMitmCapture(c, emit)

	// Under the stub (no cgo tag), this must be silent — no warning emitted,
	// matching the ErrRustNotLinked convention used throughout pkg/ncer.
	for _, msg := range logged {
		t.Errorf("unexpected emitted log during stub/linked drain: %q", msg)
	}
}
