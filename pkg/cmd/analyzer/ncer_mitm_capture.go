package main

import (
	"errors"

	"mega-analyzer/pkg/ncer"
	"mega-analyzer/pkg/ncer/mitmbridge"
)

// feedNcerMitmCapture drains the Rust omnisec-mitm live-capture accumulator
// (see rust/crates/omnisec-mitm/src/lib.rs's CAPTURE_STORE) and merges
// whatever it holds into collector, converging the Rust live-capture
// pipeline with the Go telemetry-replay pipeline described in
// docs/ncer/Architecture.md.
//
// A safe no-op in the common case: without the 'cgo omnisec_mitm_ffi' build
// tag mitmbridge.TakeCapture returns ErrRustNotLinked (silently ignored,
// same convention as reconcile.ErrRustNotLinked); with the tag but no proxy
// runner ever started this session, it returns an empty capture.
func feedNcerMitmCapture(collector *ncer.Collector, emit func(TelemetryEvent)) {
	data, err := mitmbridge.TakeCapture()
	if err != nil {
		if !errors.Is(err, mitmbridge.ErrRustNotLinked) {
			emit(TelemetryEvent{Type: "log", Details: "⚠ NCER mitm capture drain warning: " + err.Error()})
		}
		return
	}
	if err := collector.MergeMitmCaptureJSON(data); err != nil {
		emit(TelemetryEvent{Type: "log", Details: "⚠ NCER mitm capture merge warning: " + err.Error()})
	}
}
