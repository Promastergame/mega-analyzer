//go:build !cgo || !omnisec_mitm_ffi

// Package mitmbridge exposes the Rust omnisec-mitm live-capture accumulator
// to Go. This file is the stub that compiles when the native library is
// absent or cgo is disabled — see bridge.go's doc comment for the real
// bridge and build instructions.
package mitmbridge

import "errors"

// ErrRustNotLinked is returned by the stub when the native library is
// absent. Callers should check errors.Is(err, ErrRustNotLinked) to detect
// this case and fall back gracefully.
var ErrRustNotLinked = errors.New("omnisec-mitm not linked: rebuild with -tags 'cgo omnisec_mitm_ffi'")

// TakeCapture is a stub that always returns ErrRustNotLinked.
func TakeCapture() ([]byte, error) {
	return nil, ErrRustNotLinked
}
