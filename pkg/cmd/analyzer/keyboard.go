package main

import "errors"

// errTUIUnsupported is returned by newRawTerm on platforms where the
// interactive wizard isn't implemented yet. Callers should treat it as
// a signal to drop into -no-tui mode.
var errTUIUnsupported = errors.New("interactive TUI is not supported on this platform yet — use -no-tui")

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
	keyDelete
	keyShiftTab
	keyPaste
	keyInterrupt
)

type keyEvent struct {
	kind keyKind
	r    rune
	text string // complete bracketed paste, delivered as a single edit
}
