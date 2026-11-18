//go:build !windows

package main

// ═══════════════════════════════════════════════════════════════════════════════
// KEYBOARD STUB — non-Windows platforms
//
// The interactive TUI is Windows-only for now. On Linux/macOS the wizard
// is bypassed and the analyzer runs in classic CLI mode (-no-tui).
// errTUIUnsupported lives in keyboard.go and is shared across platforms.
// ═══════════════════════════════════════════════════════════════════════════════

type rawTerm struct{}

func newRawTerm() (*rawTerm, error) {
	return nil, errTUIUnsupported
}

func (r *rawTerm) Close()                           {}
func (r *rawTerm) HideCursor()                      {}
func (r *rawTerm) ShowCursor()                      {}
func (r *rawTerm) EnterAltScreen()                  {}
func (r *rawTerm) ReadKey() (keyEvent, error)       { return keyEvent{}, errTUIUnsupported }
func (r *rawTerm) PollKey(uint32) (keyEvent, error) { return keyEvent{}, errTUIUnsupported }
