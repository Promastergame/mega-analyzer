//go:build !windows

package main

// ═══════════════════════════════════════════════════════════════════════════════
// KEYBOARD STUB — non-Windows platforms
//
// The interactive TUI is Windows-only for now. On Linux/macOS the wizard
// is bypassed and the analyzer runs in classic CLI mode (-no-tui).
// errTUIUnsupported lives in keyboard.go and is shared across platforms.
// ═══════════════════════════════════════════════════════════════════════════════

type keyKind int

const (
	keyNone keyKind = iota
	keyChar
	keyEnter
	keyEsc
	keyBackspace
	keyTab
	keyUp
	keyDown
	keyLeft
	keyRight
	keyHome
	keyEnd
	keyPgUp
	keyPgDn
	keyF1
)

type keyEvent struct {
	kind keyKind
	r    rune
}

type rawTerm struct{}

func newRawTerm() (*rawTerm, error) {
	return nil, errTUIUnsupported
}

func (r *rawTerm) Close()                     {}
func (r *rawTerm) HideCursor()                {}
func (r *rawTerm) ShowCursor()                {}
func (r *rawTerm) EnterAltScreen()            {}
func (r *rawTerm) ReadKey() (keyEvent, error) { return keyEvent{}, errTUIUnsupported }
