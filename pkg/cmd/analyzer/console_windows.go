//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// Console Win32 helpers implemented directly on top of the standard library's
// syscall package instead of golang.org/x/sys/windows. This keeps the project
// dependency-free and cross-compilable with a plain `go build` (no cgo, no
// external toolchain). modKernel32 is declared in procstat_windows.go (same
// package, windows-only build).
var (
	procGetConsoleMode             = modKernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = modKernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = modKernel32.NewProc("GetConsoleScreenBufferInfo")
)

// Console input/output mode flags (see the Win32 SetConsoleMode docs).
const (
	enableProcessedInput uint32 = 0x0001
	enableLineInput      uint32 = 0x0002
	enableEchoInput      uint32 = 0x0004
	enableMouseInput     uint32 = 0x0010
	cWaitObject0         uint32 = 0x00000000
)

type consoleCoord struct{ X, Y int16 }

type consoleSmallRect struct{ Left, Top, Right, Bottom int16 }

// consoleScreenBufferInfo mirrors CONSOLE_SCREEN_BUFFER_INFO.
type consoleScreenBufferInfo struct {
	Size              consoleCoord
	CursorPosition    consoleCoord
	Attributes        uint16
	Window            consoleSmallRect
	MaximumWindowSize consoleCoord
}

func getConsoleMode(h syscall.Handle) (uint32, error) {
	var mode uint32
	r1, _, e := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r1 == 0 {
		return 0, e
	}
	return mode, nil
}

func setConsoleMode(h syscall.Handle, mode uint32) error {
	r1, _, e := procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	if r1 == 0 {
		return e
	}
	return nil
}

func getConsoleScreenBufferInfo(h syscall.Handle, info *consoleScreenBufferInfo) error {
	r1, _, e := procGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(info)))
	if r1 == 0 {
		return e
	}
	return nil
}
