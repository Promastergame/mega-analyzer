//go:build windows

package main

import (
	"os"
	"syscall"
)

// ═══════════════════════════════════════════════════════════════════════════════
// KEYBOARD — raw-mode single-key reader for Windows
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
	r    rune // valid when kind == keyChar
}

// rawTerm captures the terminal mode and restores it on Close.
type rawTerm struct {
	stdin        syscall.Handle
	stdout       syscall.Handle
	prevIn       uint32
	prevOut      uint32
	cursorHidden bool
	altScreen    bool
}

func newRawTerm() (*rawTerm, error) {
	stdin := syscall.Handle(os.Stdin.Fd())
	stdout := syscall.Handle(os.Stdout.Fd())

	prevIn, err := getConsoleMode(stdin)
	if err != nil {
		return nil, err
	}
	prevOut, err := getConsoleMode(stdout)
	if err != nil {
		return nil, err
	}

	// Stdin: disable line input + echo + processed input so we get raw keys.
	// Keep window/mouse input flag off so we only read keystrokes.
	const enableVTInput uint32 = 0x0200
	newIn := prevIn &^ (enableLineInput |
		enableEchoInput |
		enableProcessedInput |
		enableMouseInput)
	newIn |= enableVTInput
	if err := setConsoleMode(stdin, newIn); err != nil {
		return nil, err
	}

	// Stdout: make sure VT processing is on so our ANSI sequences work.
	const enableVTOutput uint32 = 0x0004
	newOut := prevOut | enableVTOutput
	_ = setConsoleMode(stdout, newOut)

	return &rawTerm{
		stdin:   stdin,
		stdout:  stdout,
		prevIn:  prevIn,
		prevOut: prevOut,
	}, nil
}

func (r *rawTerm) Close() {
	if r == nil {
		return
	}
	if r.cursorHidden {
		os.Stdout.Write([]byte("\x1b[?25h"))
		r.cursorHidden = false
	}
	if r.altScreen {
		// Restore main screen buffer + scrollback.
		os.Stdout.Write([]byte("\x1b[?1049l"))
		r.altScreen = false
	}
	_ = setConsoleMode(r.stdin, r.prevIn)
	_ = setConsoleMode(r.stdout, r.prevOut)
}

// EnterAltScreen switches to the terminal's alternate screen buffer.
func (r *rawTerm) EnterAltScreen() {
	if r == nil || r.altScreen {
		return
	}
	os.Stdout.Write([]byte("\x1b[?1049h"))
	r.altScreen = true
}

func (r *rawTerm) HideCursor() {
	if r == nil || r.cursorHidden {
		return
	}
	os.Stdout.Write([]byte("\x1b[?25l"))
	r.cursorHidden = true
}

func (r *rawTerm) ShowCursor() {
	if r == nil || !r.cursorHidden {
		return
	}
	os.Stdout.Write([]byte("\x1b[?25h"))
	r.cursorHidden = false
}

// ReadKey reads one logical keystroke. It blocks until something is read.
func (r *rawTerm) ReadKey() (keyEvent, error) {
	buf := make([]byte, 1)
	n, err := os.Stdin.Read(buf)
	if err != nil {
		return keyEvent{}, err
	}
	if n == 0 {
		return keyEvent{kind: keyNone}, nil
	}
	b := buf[0]

	switch b {
	case 0x0d, 0x0a:
		return keyEvent{kind: keyEnter}, nil
	case 0x09:
		return keyEvent{kind: keyTab}, nil
	case 0x08, 0x7f:
		return keyEvent{kind: keyBackspace}, nil
	case 0x1b:
		return r.readEscape()
	case 0x03: // Ctrl+C -> route through the same quit key as 'q'
		return keyEvent{kind: keyChar, r: 'q'}, nil
	case 0x0b: // Ctrl+K
		return keyEvent{kind: keyChar, r: rune(b)}, nil
	case 0x10: // Ctrl+P
		return keyEvent{kind: keyChar, r: rune(b)}, nil
	}
	if b >= 0x20 && b < 0x7f {
		return keyEvent{kind: keyChar, r: rune(b)}, nil
	}
	// UTF-8 lead byte
	if b >= 0xc0 {
		return r.readUTF8(b)
	}
	return keyEvent{kind: keyNone}, nil
}

const escFollowupTimeoutMs = 25

// waitReadable reports whether stdin has a byte available within timeoutMs.
func (r *rawTerm) waitReadable(timeoutMs uint32) bool {
	event, err := syscall.WaitForSingleObject(r.stdin, timeoutMs)
	if err != nil {
		return false
	}
	return event == cWaitObject0
}

func (r *rawTerm) readEscape() (keyEvent, error) {
	if !r.waitReadable(escFollowupTimeoutMs) {
		return keyEvent{kind: keyEsc}, nil
	}
	buf := make([]byte, 1)
	n, err := os.Stdin.Read(buf)
	if err != nil || n == 0 {
		return keyEvent{kind: keyEsc}, nil
	}
	if buf[0] != '[' && buf[0] != 'O' {
		return keyEvent{kind: keyEsc}, nil
	}
	isSS3 := buf[0] == 'O'
	if !r.waitReadable(escFollowupTimeoutMs) {
		return keyEvent{kind: keyEsc}, nil
	}
	final := make([]byte, 1)
	n, err = os.Stdin.Read(final)
	if err != nil || n == 0 {
		return keyEvent{kind: keyEsc}, nil
	}
	switch final[0] {
	case 'A':
		return keyEvent{kind: keyUp}, nil
	case 'B':
		return keyEvent{kind: keyDown}, nil
	case 'C':
		return keyEvent{kind: keyRight}, nil
	case 'D':
		return keyEvent{kind: keyLeft}, nil
	case 'H':
		return keyEvent{kind: keyHome}, nil
	case 'F':
		return keyEvent{kind: keyEnd}, nil
	case 'P':
		if isSS3 {
			return keyEvent{kind: keyF1}, nil
		}
	case '5', '6':
		drain := make([]byte, 1)
		os.Stdin.Read(drain)
		if final[0] == '5' {
			return keyEvent{kind: keyPgUp}, nil
		}
		return keyEvent{kind: keyPgDn}, nil
	}
	return keyEvent{kind: keyEsc}, nil
}

func (r *rawTerm) readUTF8(lead byte) (keyEvent, error) {
	var more int
	switch {
	case lead&0xe0 == 0xc0:
		more = 1
	case lead&0xf0 == 0xe0:
		more = 2
	case lead&0xf8 == 0xf0:
		more = 3
	default:
		return keyEvent{kind: keyNone}, nil
	}
	buf := make([]byte, more+1)
	buf[0] = lead
	if _, err := os.Stdin.Read(buf[1:]); err != nil {
		return keyEvent{kind: keyNone}, err
	}
	rs := []rune(string(buf))
	if len(rs) == 0 {
		return keyEvent{kind: keyNone}, nil
	}
	return keyEvent{kind: keyChar, r: rs[0]}, nil
}
