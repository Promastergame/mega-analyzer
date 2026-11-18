package semai

import "os"

// accel is an optional native implementation of the Transformer layers
// (embedding LayerNorm + encoder layers). x holds n×hidden embeddings and is
// overwritten with the last hidden states; false means "not handled".
type accel interface {
	forward(x []float32, n int) bool
}

// newAccel is set by accel_nim.go when built with `-tags nim` (cgo + Nim static lib).
var newAccel func(e *Encoder) accel

// nimKind reports the Nim build flavour (bit 1 = FASM kernel, bit 2 = OpenMP).
var nimKind func() int

// AccelName is a human-readable name of what runs the Transformer layers in this binary.
func AccelName() string {
	if newAccel == nil || nimKind == nil {
		return "Go"
	}
	if os.Getenv("DAI_NO_NIM") != "" {
		return "Go (Nim выключен DAI_NO_NIM)"
	}
	k, n := nimKind(), "Nim"
	if k&1 != 0 {
		n += "+FASM"
	}
	if k&2 != 0 {
		n += "+OpenMP"
	}
	return n
}

// Native reports which native backend runs the encoder layers ("" = pure Go).
func (e *Encoder) Native() string {
	if e != nil && e.acc != nil {
		return "nim"
	}
	return ""
}
