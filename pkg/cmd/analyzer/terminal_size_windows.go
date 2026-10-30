//go:build windows

package main

import (
	"os"
	"syscall"
)

// terminalSize returns terminal width and height in characters.
// Returns (0, 0) if size cannot be determined.
func terminalSize() (cols, rows int) {
	for _, fd := range []uintptr{os.Stdout.Fd(), os.Stderr.Fd(), os.Stdin.Fd()} {
		var info consoleScreenBufferInfo
		if err := getConsoleScreenBufferInfo(syscall.Handle(fd), &info); err == nil {
			c := int(info.Window.Right - info.Window.Left + 1)
			r := int(info.Window.Bottom - info.Window.Top + 1)
			if c > 0 && r > 0 {
				return c, r
			}
		}
	}
	return 0, 0
}
