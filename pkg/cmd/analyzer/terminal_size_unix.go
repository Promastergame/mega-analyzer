//go:build !windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// winsize mirrors the kernel's struct winsize used by the TIOCGWINSZ ioctl.
type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// terminalSize returns terminal width and height in characters.
// Returns (0, 0) if size cannot be determined. Uses a raw TIOCGWINSZ ioctl via
// the standard library syscall package (no golang.org/x/sys dependency).
func terminalSize() (cols, rows int) {
	for _, fd := range []int{int(os.Stdout.Fd()), int(os.Stderr.Fd()), int(os.Stdin.Fd())} {
		var ws winsize
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(syscall.TIOCGWINSZ),
			uintptr(unsafe.Pointer(&ws)),
		)
		if errno == 0 && ws.Col > 0 && ws.Row > 0 {
			return int(ws.Col), int(ws.Row)
		}
	}
	return 0, 0
}
