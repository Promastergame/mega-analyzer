// Tests for pkg/ncer/mitmbridge.
//
// These run in every build — with and without cgo — because they only
// exercise the observable contract (an error the caller can check with
// errors.Is, or a byte slice), not internal wiring.
package mitmbridge

import (
	"errors"
	"testing"
)

// TestTakeCapture_StubOrLinked verifies TakeCapture behaves per its
// documented contract regardless of which build variant is active: the
// stub always returns ErrRustNotLinked, the real bridge never returns that
// error (an empty store is (nil, nil), not a failure).
func TestTakeCapture_StubOrLinked(t *testing.T) {
	data, err := TakeCapture()
	if err != nil {
		if !errors.Is(err, ErrRustNotLinked) {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	// Real bridge: the store is lazily created empty on first access, so a
	// fresh process's first drain returns valid (empty-array) JSON, not nil.
	if data == nil {
		t.Fatalf("real bridge should never return (nil, nil) except on internal encode failure")
	}
}
