//go:build windows

package main

import (
	"bufio"
	"os"
	"syscall"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════════════════════
// KEYBOARD — raw-mode single-key reader for Windows
// ═══════════════════════════════════════════════════════════════════════════════

// rawTerm captures the terminal mode and restores it on Close.
type rawTerm struct {
	reader       *bufio.Reader
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
		0x0008 | // window-size records are polled through terminal dimensions
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
		reader:  bufio.NewReader(os.Stdin),
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
		os.Stdout.Write([]byte("\x1b[?2004l"))
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
	os.Stdout.Write([]byte("\x1b[?1049h\x1b[?2004h"))
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
	if r.reader == nil {
		r.reader = bufio.NewReader(os.Stdin)
	}
	return decodeKey(r.reader, func() bool {
		event, err := syscall.WaitForSingleObject(r.stdin, 25)
		return err == nil && event == cWaitObject0
	})
}

// PollKey allows redraws while idle without a second reader racing an editor.
// Console handles also signal for key-up events; discard those before using
// the byte reader, which would otherwise block waiting for a printable key.
func (r *rawTerm) PollKey(timeoutMS uint32) (keyEvent, error) {
	if r.reader != nil && r.reader.Buffered() > 0 {
		return r.ReadKey()
	}
	ready, err := syscall.WaitForSingleObject(r.stdin, timeoutMS)
	if err != nil {
		return keyEvent{}, err
	}
	if ready != cWaitObject0 {
		return keyEvent{kind: keyNone}, nil
	}
	var record struct {
		kind                        uint16
		pad                         uint16
		down                        int32
		repeat, virtual, scan, char uint16
		control                     uint32
	}
	var count uint32
	peek := syscall.NewLazyDLL("kernel32.dll").NewProc("PeekConsoleInputW")
	read := syscall.NewLazyDLL("kernel32.dll").NewProc("ReadConsoleInputW")
	ok, _, callErr := peek.Call(uintptr(r.stdin), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return keyEvent{}, callErr
	}
	if count == 0 {
		return keyEvent{kind: keyNone}, nil
	}
	// Navigation keys have no Unicode character until VT input encodes them.
	navigation := record.virtual >= 0x21 && record.virtual <= 0x28 || record.virtual == 0x2e || record.virtual == 0x70
	if record.kind == 1 && record.down != 0 && (record.char != 0 || navigation) {
		return r.ReadKey()
	}
	ok, _, callErr = read.Call(uintptr(r.stdin), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return keyEvent{}, callErr
	}
	return keyEvent{kind: keyNone}, nil
}
