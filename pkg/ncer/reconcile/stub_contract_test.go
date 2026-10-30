//go:build !cgo || !omnisec_ncer_reconcile_ffi

package reconcile

import (
	"errors"
	"testing"
	"time"
)

func TestWindowedStubIsExplicitlyUnavailable(t *testing.T) {
	for _, window := range []time.Duration{0, time.Second, -time.Second} {
		result, err := RunReconcileWindowed([]byte(`{"http_requests":[]}`), window)
		if result != nil || !errors.Is(err, ErrRustNotLinked) {
			t.Fatalf("window=%v result=%+v err=%v", window, result, err)
		}
	}
}
