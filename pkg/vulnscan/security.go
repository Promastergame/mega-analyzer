package vulnscan

import "runtime"

// HardenBrowserSandbox controls whether the headless Chrome used for DOM
// discovery runs with its OS sandbox enabled. The default is true: the
// sandbox is the single most important browser defense. Container/CI
// environments that run Chrome as root and cannot use the sandbox must set
// HardenBrowserSandbox=false explicitly to fall back to --no-sandbox.
var HardenBrowserSandbox = true

// zeroize overwrites a byte slice with zeros. For a security tool, secrets
// (JWT wordlist entries, extracted credentials) should not linger in the heap
// after use. runtime.KeepAlive prevents the compiler from optimizing the write
// away as dead.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroizeBytes is the exported entry point for zeroizing sensitive buffers.
func ZeroizeBytes(b []byte) { zeroize(b) }

// ZeroizeStrings zeroizes the backing arrays of a slice of secret strings by
// converting them to mutable byte copies is not possible in Go (strings are
// immutable); callers holding secrets as []byte should use ZeroizeBytes. This
// helper clears the slice header references so the GC can reclaim them sooner.
func ZeroizeStrings(ss []string) {
	for i := range ss {
		ss[i] = ""
	}
}
