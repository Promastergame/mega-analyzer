//go:build windows

package native

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// debuggerDLL resolves the Rust debugger library WITHOUT the default
// LoadLibrary search order. The old NewLazyDLL("omnisec_debugger_ffi.dll")
// honored CWD/PATH, so a crafted DLL shipped next to an analyzed file (or
// any writable PATH entry) executed inside the analyzer. We only trust the
// directory next to the running executable and System32, both by absolute
// path — an absolute LoadLibrary name skips the search order entirely.
func debuggerDLL() *syscall.LazyDLL {
	const name = "omnisec_debugger_ffi.dll"
	if exe, err := os.Executable(); err == nil {
		local := filepath.Join(filepath.Dir(exe), name)
		if _, statErr := os.Stat(local); statErr == nil {
			return syscall.NewLazyDLL(local)
		}
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	return syscall.NewLazyDLL(filepath.Join(strings.TrimSpace(sysRoot), "System32", name))
}

var (
	dll = debuggerDLL()

	procStart       = dll.NewProc("omnisec_debugger_start")
	procStop        = dll.NewProc("omnisec_debugger_stop")
	procDebuggerCmd = dll.NewProc("omnisec_debugger_command")
	procFree        = dll.NewProc("omnisec_debugger_free")

	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procLstrlenA      = kernel32.NewProc("lstrlenA")
	procRtlMoveMemory = kernel32.NewProc("RtlMoveMemory")
)

// Native talks to the Rust debugger engine via Windows DLL (no CGO needed).
type Native struct{}

// NewNative creates a new native debugger handle.
func NewNative() *Native { return &Native{} }

func goCString(ptr unsafe.Pointer) string {
	s, _ := cStringFromAddress(uintptr(ptr))
	return s
}

func cStringFromAddress(addr uintptr) (string, error) {
	if addr == 0 {
		return "", nil
	}
	n, _, err := procLstrlenA.Call(addr)
	if n == 0 {
		if err != syscall.Errno(0) {
			return "", err
		}
		return "", nil
	}
	const maxCString = 1 << 20
	if n > maxCString {
		return "", fmt.Errorf("C string too large: %d bytes", n)
	}
	buf := make([]byte, n)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&buf[0])), addr, n)
	return string(buf), nil
}

func (n *Native) command(sessionID uint64, cmd map[string]interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	cp, err := syscall.BytePtrFromString(string(b))
	if err != nil {
		// A NUL inside the serialized payload would have produced a nil
		// pointer handed straight to the FFI.
		return nil, fmt.Errorf("encode command: %w", err)
	}
	ret, _, _ := procDebuggerCmd.Call(uintptr(unsafe.Pointer(cp)))
	if ret == 0 {
		return nil, fmt.Errorf("command returned null")
	}
	s, readErr := cStringFromAddress(ret)
	procFree.Call(ret)
	if readErr != nil {
		return nil, readErr
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Start opens a session. Returns session_id (0 on error).
func (n *Native) Start(filePath string, entry uint64) uint64 {
	cp, err := syscall.BytePtrFromString(filePath)
	if err != nil {
		return 0
	}
	ret, _, _ := procStart.Call(uintptr(unsafe.Pointer(cp)), uintptr(entry))
	return uint64(ret)
}

// Stop destroys a session.
func (n *Native) Stop(sessionID uint64) {
	procStop.Call(uintptr(sessionID))
}

// Step executes one instruction.
func (n *Native) Step(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "step"})
}

// Continue runs until stop.
func (n *Native) Continue(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "continue"})
}

// Registers reads CPU state.
func (n *Native) Registers(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "registers"})
}

// Disassemble returns count instructions at address.
func (n *Native) Disassemble(sessionID uint64, address uint64, count int) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command": "disassemble",
		"address": address,
		"count":   count,
	})
}

// ReadMemory reads raw bytes.
func (n *Native) ReadMemory(sessionID uint64, address uint64, size uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command": "read_memory",
		"address": address,
		"size":    size,
	})
}

// WriteMemory patches memory with hex string.
func (n *Native) WriteMemory(sessionID uint64, address uint64, hex string) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command":  "write_memory",
		"address":  address,
		"hex_data": hex,
	})
}

// SetRegister changes a register.
func (n *Native) SetRegister(sessionID uint64, reg string, value uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command":  "set_register",
		"register": reg,
		"value":    value,
	})
}

// Breakpoint sets a breakpoint by address or symbol.
func (n *Native) Breakpoint(sessionID uint64, target string) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command": "breakpoint",
		"target":  target,
	})
}

// RemoveBreakpoint removes a breakpoint by id.
func (n *Native) RemoveBreakpoint(sessionID uint64, id uint32) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command": "remove_breakpoint",
		"id":      id,
	})
}

// SetFlavor changes disassembly syntax (intel/att).
func (n *Native) SetFlavor(sessionID uint64, flavor string) {
	_, _ = n.command(sessionID, map[string]interface{}{
		"command": "set_flavor",
		"flavor":  flavor,
	})
}

// Next steps over calls (step one instruction, skip calls).
func (n *Native) Next(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "next"})
}

// TraceEnable toggles time-travel tracing.
func (n *Native) TraceEnable(sessionID uint64, enabled bool) {
	_, _ = n.command(sessionID, map[string]interface{}{
		"command": "trace_enable",
		"enabled": enabled,
	})
}

// ReverseStep rewinds one instruction (requires trace enabled).
func (n *Native) ReverseStep(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "reverse_step"})
}

// ReverseContinue rewinds until previous breakpoint.
func (n *Native) ReverseContinue(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "reverse_continue"})
}

// ScanMemory searches for a byte pattern (hex with ?? wildcards).
func (n *Native) ScanMemory(sessionID uint64, pattern string) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{
		"command": "scan_memory",
		"pattern": pattern,
	})
}
