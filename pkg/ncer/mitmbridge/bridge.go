//go:build cgo && omnisec_mitm_ffi

// Package mitmbridge exposes the Rust omnisec-mitm live-capture accumulator
// to Go via the omnisec-mitm shared library, so a running analysis session
// can drain real SSL-strip/DNS-spoof/obfs-proxy observations (see
// rust/crates/omnisec-mitm/src/lib.rs's CAPTURE_STORE) into the same
// MitmCapture JSON shape ncer.Collector already builds from telemetry
// replay. Building without this tag (the default) makes TakeCapture a no-op
// that returns (nil, ErrRustNotLinked) — see bridge_stub.go.
//
// Build with:
//
//	go build -tags 'cgo omnisec_mitm_ffi' ./...
//
// This bridge only exposes the drain side (omnisec_mitm_take_capture). It
// deliberately does not start the SSL-strip/DNS-spoof/obfs proxies
// themselves — nothing in this repository's live analyzer flow does that
// today (see docs/ncer/Architecture.md); starting them is a separate,
// much larger change (root/CAP_NET_ADMIN, DHCP spoofing, device cert trust)
// than "let Go read what Rust already accumulated."
package mitmbridge

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../rust/target/release -lomnisec_mitm
#include <stdlib.h>

// Drains the shared live-capture accumulator, lazily creating it (empty) if
// this is the first call in the process. Returns NULL only on JSON encode
// failure or a poisoned store mutex — an unused store still returns valid
// (empty-array) JSON, never NULL. The caller must free a non-NULL result
// with omnisec_mitm_free_str.
extern char* omnisec_mitm_take_capture(void);

// Frees a string previously returned by omnisec_mitm_take_capture.
extern void omnisec_mitm_free_str(char* ptr);
*/
import "C"
import (
	"errors"
)

// ErrRustNotLinked is returned by the stub when the native library is
// absent. Defined here too so it is available under both build variants.
var ErrRustNotLinked = errors.New("omnisec-mitm not linked: rebuild with -tags 'cgo omnisec_mitm_ffi'")

// TakeCapture drains the Rust live-capture accumulator and returns its
// contents as raw MitmCapture JSON bytes: `{"http_requests":[],...}` with
// all five arrays empty when no proxy runner observed anything this
// session — that's the expected common case in this repository today (see
// the package doc), not a failure. Returns (nil, nil), not an error, only
// on the rare internal failure the Rust side signals with NULL (JSON encode
// failure or a poisoned store mutex).
func TakeCapture() ([]byte, error) {
	cOut := C.omnisec_mitm_take_capture()
	if cOut == nil {
		return nil, nil
	}
	defer C.omnisec_mitm_free_str(cOut)

	return []byte(C.GoString(cOut)), nil
}
