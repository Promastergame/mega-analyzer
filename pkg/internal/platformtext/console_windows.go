//go:build windows

package platformtext

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	getConsoleOutputCP  = kernel32.NewProc("GetConsoleOutputCP")
	getOEMCP            = kernel32.NewProc("GetOEMCP")
	multiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
)

func decodeLegacyConsole(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	cp, _, _ := getConsoleOutputCP.Call()
	// UTF-8 was checked first. A windowless netsh process generally falls back
	// to the system OEM page even when its parent has no attached console.
	if cp == 0 || cp == 65001 {
		cp, _, _ = getOEMCP.Call()
	}
	if cp == 0 {
		cp = 1
	} // CP_OEMCP
	return decodeConsoleCodePage(data, cp)
}
func decodeConsoleCodePage(data []byte, cp uintptr) string {
	if len(data) == 0 {
		return ""
	}
	size, _, _ := multiByteToWideChar.Call(cp, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, 0)
	if size == 0 {
		return strings.ToValidUTF8(string(data), "\ufffd")
	}
	buf := make([]uint16, int(size))
	count, _, _ := multiByteToWideChar.Call(cp, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&buf[0])), size)
	if count == 0 {
		return strings.ToValidUTF8(string(data), "\ufffd")
	}
	return syscall.UTF16ToString(buf[:int(count)])
}
