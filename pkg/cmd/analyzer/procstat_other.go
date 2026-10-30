//go:build !windows

package main

// sampleHostStats is unavailable off Windows; the dashboard hides the CPU/RAM
// bars when ok is false rather than showing synthesized values.
func sampleHostStats() (cpuPct int, ramPct int, ok bool) {
	return 0, 0, false
}
