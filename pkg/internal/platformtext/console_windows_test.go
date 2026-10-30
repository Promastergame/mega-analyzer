//go:build windows

package platformtext

import "testing"

func TestSandboxReliabilityWindowsOEM(t *testing.T) {
	raw := []byte{0x8f, 0xe0, 0xa0, 0xa2, 0xa0}
	if got := decodeConsoleCodePage(raw, 866); got != "Права" {
		t.Fatalf("CP866 = %q", got)
	}
}
